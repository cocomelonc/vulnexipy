# vulnexipy

**Vulnerabilities exploitation examples**

## Examples

CVE-2016-6210 - sshd in OpenSSH before 7.3, when SHA256 or SHA512 are used for user password hashing, uses BLOWFISH hashing on a static password when the username does not exist, which allows remote attackers to enumerate users by leveraging the timing difference between responses when a large password is provided.

```bash
python cve_2016_6210.py --target 10.10.6.17 --usernames users.txt
```
CVE-2016-6515 - The auth_password function in auth-passwd.c in sshd in OpenSSH before 7.3 does not limit password lengths for password authentication, which allows remote attackers to cause a denial of service (crypt CPU consumption) via a long string. 

```bash
python cve_2016_6515.py --target 10.10.6.13 --username root
```

CVE-2019-16113 - Bludit 3.9.2 allows remote code execution via bl-kernel/ajax/upload-images.php because PHP code can be entered with a .jpg file name, and then this PHP code can write other PHP code to a ../ pathname.

```bash
python cve_2019_16113 --url 10.10.6.15 --username admin --password admin --cmd whoami
```

**For Educational Purposes Only!!!**
**Author takes no responsibility of any damage you cause**
