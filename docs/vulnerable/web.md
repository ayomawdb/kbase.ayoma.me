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

## Magento

ExploitDB: 37977 (change password), 37811

- https://dustri.org/b/writing-a-simple-extensionbackdoor-for-magento.html
- https://www.foregenix.com/blog/anatomy-of-a-magento-attack-froghopper
- http://www.ethanjoachimeldridge.info/tech-blog/exploiting-magento
- https://0xdf.gitlab.io/2019/09/28/htb-swagshop.html

Plugins to exploit: 
- https://pluginarchive.com/magento/magpleasure_filesystem
- https://github.com/lavalamp-/LavaMagentoBD

# HelpDeskZ - RCE
- https://github.com/weaknetlabs/Penetration-Testing-Grimoire/blob/master/Vulnerabilities/Web/helpdeskz-file-enum.md