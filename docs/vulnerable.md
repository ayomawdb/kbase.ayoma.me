## Desktop Applications

- Chkrootkit 0.49
  - Prev Esc
  - <https://www.exploit-db.com/exploits/33899>
- Mozilla Firefox < 45.0
  - RCE
  - <https://www.exploit-db.com/exploits/42484>
- Zervit 0.4 
- Acrobat Reader version 8.1.2 – <ftp://ftp.adobe.com/pub/adobe/reader/win/8.x/8.1.2/enu/AdbeRdr812_en_US.exe>
- Java 7 Update 6 JRE – <http://www.oracle.com/technetwork/java/javase/downloads/java-archive-downloads-javase7-521261.html>
- Winamp 5.5 – <http://www.filehorse.com/download-winamp/4137/download/>

## Server Applications

- HttpFileServer 2.3x before 2.3c
  - CVE-2014-6287
  - RCE
  - <https://www.exploit-db.com/exploits/39161>
  - `exploit/windows/http/rejetto_hfs_exec`
- AChat 0.150 beta7
  - Buffer Overflow
  - <https://www.exploit-db.com/exploits/36025>
  - `exploit/windows/misc/achat_bof`
- Apache James 2.3.2
  - RCE
  - <https://www.exploit-db.com/exploits/35513/> 
  - [htb_solidstate](https://dominicbreuker.com/post/htb_solidstate/)
- Elastix 2.2.0
  - LFI
  - <https://www.exploit-db.com/exploits/37637>
- ColdFusion 8.0.1
  - CVE-2009-2265
  - File upload
  - <https://arrexel.com/coldfusion-8-0-1-arbitrary-file-upload/>
  - `exploit/windows/http/coldfusion_fckeditor`
- Xdebug 
  - RCE
  - <https://github.com/gteissier/xdebug-shell>
  - <https://github.com/vulhub/vulhub/tree/master/php/xdebug-rce>
- IRCD 3.2.8.1
  - CVE-2010-2075
  - RCE
  - <https://www.exploit-db.com/exploits/13853>
  - `exploit/unix/irc/unreal_ircd_3281_backdoor`
- Haraka SMTP < 2.8.9
  - RCE
  - <https://www.exploit-db.com/exploits/41162>
- Zabbix 2.2 < 3.0.3
  - RCE
  - <https://www.exploit-db.com/exploits/39937>
- CouchDB < 2.1.0
  - CVE-2017-12636
  - RCE
  - <https://www.exploit-db.com/exploits/44913/>
  - <https://justi.cz/security/2017/11/14/couchdb-rce-npm.html>
- PlaySMS 1.4
  - RCE
  - <https://www.exploit-db.com/exploits/42044>
- ImageMagick < 6.9.3-9
  - CVE-2016–3714
  - RCE
- dompdf 0.6.0
  - LFI
  - <https://www.exploit-db.com/exploits/33004/>
- vsftpd 2.3.4
  - Shell / RCE / Backdoor
  - <https://github.com/In2econd/vsftpd-2.3.4-exploit/blob/master/vsftpd_234_exploit.py>
  - `exploit/unix/ftp/vsftpd_234_backdoor`
- SLMail
- WarFTP 1.65
- XAMPP 1.7.2 – <https://www.exploit-db.com/exploits/10391/>
- 3Com TFTP 2.0.1

## Web Applications

- Pfsense <= 2.2.6
  - Command Injection
  - <https://www.exploit-db.com/exploits/39709/>
- Drupal 7.x 
  - RCE
  - <https://www.exploit-db.com/exploits/41564>
- October CMS 1.0.412
  - RCE, PHP object injection
  - <https://www.exploit-db.com/exploits/41936>
- NibbleBlog 
  - Usernames: /nibbleblog/content/private/users.xml 
- Apache Struts 2.3.x before 2.3.32 2.5.x before 2.5.10.1
  - RCE
  - CVE-2017-5638
  - <https://github.com/mazen160/struts-pwn>
- PHPLiteAdmin 1.9.2
  - RCE
  - <https://www.exploit-db.com/exploits/24044>
- PiHole
  - `sudo pihole -a -p PASSWORD`
- UnrealIRCD 3.2.8.1
  - Backdoor RCE
  - <https://www.exploit-db.com/exploits/16922>
- HelpDeskZ 
  - RCE
  - <https://github.com/weaknetlabs/Penetration-Testing-Grimoire/blob/master/Vulnerabilities/Web/helpdeskz-file-enum.md>

### Pfsense

- Pfsense < 2.1.4
  - Command Injection
  - <https://www.exploit-db.com/exploits/43560>
- [PfSense Vulnerabilities Part 2: Command Injection - <https://www.proteansec.com/linux/pfsense-vulnerabilities-part-2-command-injection/>
- [PfSense Vulnerabilities Part 3: Local File Inclusion - <https://www.proteansec.com/linux/pfsense-vulnerabilities-part-3-local-file-inclusion/>
- [PfSense Vulnerabilities Part 4: Directory Traversal - <https://www.proteansec.com/linux/pfsense-vulnerabilities-part-4-directory-traversal/>

### Magento

ExploitDB: 37977 (change password), 37811

- <https://dustri.org/b/writing-a-simple-extensionbackdoor-for-magento.html>
- <https://www.foregenix.com/blog/anatomy-of-a-magento-attack-froghopper>
- <http://www.ethanjoachimeldridge.info/tech-blog/exploiting-magento>
- <https://0xdf.gitlab.io/2019/09/28/htb-swagshop.html>

Plugins to exploit: 

- <https://pluginarchive.com/magento/magpleasure_filesystem>
- <https://github.com/lavalamp-/LavaMagentoBD>
