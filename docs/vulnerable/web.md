# Vulnerable Web Applications

Software      | Version                                   | Vulnerability                | References                                               | Msf
:------------ | :---------------------------------------- | :--------------------------- | :------------------------------------------------------- | :--
Pfsense       | <= 2.2.6                                  | Command Injection            | [exploit-db](https://www.exploit-db.com/exploits/39709/) |
Pfsense       | < 2.1.4                                   | Command Injection            | [exploit-db](https://www.exploit-db.com/exploits/43560)  |
Drupal        | 7.x                                       | RCE                          | [exploit-db](https://www.exploit-db.com/exploits/41564)  |
October CMS   | 1.0.412                                   | RCE, PHP object injection    | [exploit-db](https://www.exploit-db.com/exploits/41936)  |
NibbleBlog    | 0                                         | Usernames                    | /nibbleblog/content/private/users.xml                    |
Apache Struts | 2.3.x before 2.3.32 2.5.x before 2.5.10.1 | RCE                          | CVE-2017-5638 <https://github.com/mazen160/struts-pwn>   |
PHPLiteAdmin  | 1.9.2                                     | RCE                          | [exploit-db](https://www.exploit-db.com/exploits/24044)  |
PiHole        | ANY                                       | `sudo pihole -a -p PASSWORD` |                                                          |
UnrealIRCD    | 3.2.8.1                                   | Backdoor RCE                 | [exploit-db](https://www.exploit-db.com/exploits/16922)  |

## Pfsense issues

- [PfSense Vulnerabilities Part 2: Command Injection - https://www.proteansec.com/linux/pfsense-vulnerabilities-part-2-command-injection/](https://www.proteansec.com/linux/pfsense-vulnerabilities-part-2-command-injection/)
- [PfSense Vulnerabilities Part 3: Local File Inclusion - https://www.proteansec.com/linux/pfsense-vulnerabilities-part-3-local-file-inclusion/](https://www.proteansec.com/linux/pfsense-vulnerabilities-part-3-local-file-inclusion/)
- [PfSense Vulnerabilities Part 4: Directory Traversal - https://www.proteansec.com/linux/pfsense-vulnerabilities-part-4-directory-traversal/](https://www.proteansec.com/linux/pfsense-vulnerabilities-part-4-directory-traversal/)
