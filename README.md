# vulnexipy

**Vulnerabilities exploitation examples**

## Example

CVE-2016-6210 - sshd in OpenSSH before 7.3, when SHA256 or SHA512 are used for user password hashing, uses BLOWFISH hashing on a static password when the username does not exist, which allows remote attackers to enumerate users by leveraging the timing difference between responses when a large password is provided.

```bash
python cve_2016_6210.py --target 10.10.6.17 --usernames users.txt
end
```
**For Educational Purposes Only!!!**
