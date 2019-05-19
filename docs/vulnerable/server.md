# Vulnerable Server Applications

| Software | Version  | CVE | Vulnerability     | References | Msf |
| :------- | :------- | :---| :---------------- | :--------- | :-- |
| HttpFileServer  | 2.3x before 2.3c  | CVE-2014-6287 | RCE | [exploit-db](https://www.exploit-db.com/exploits/39161) | exploit/windows/http/rejetto_hfs_exec |
| AChat | 0.150 beta7 | | Buffer Overflow | [exploit-db](https://www.exploit-db.com/exploits/36025) | `exploit/windows/misc/achat_bof` |
| Apache James | 2.3.2   | | RCE | [exploit-db](https://www.exploit-db.com/exploits/35513/) <br> [htb_solidstate](https://dominicbreuker.com/post/htb_solidstate/) |   |
| Elastix | 2.2.0 | | LFI | [exploit-db](https://www.exploit-db.com/exploits/37637) |   |
| ColdFusion | 8.0.1  | CVE-2009-2265 | Arbitrary file upload | [arrexel](https://arrexel.com/coldfusion-8-0-1-arbitrary-file-upload/) | exploit/windows/http/coldfusion_fckeditor |
| Xdebug |   |   | RCE | [xdebug-shell](https://github.com/gteissier/xdebug-shell) <br> [xdebug-rce](https://github.com/vulhub/vulhub/tree/master/php/xdebug-rce_) |   |
| IRCD  | 3.2.8.1 | CVE-2010-2075 | RCE | [exploit-db](https://www.exploit-db.com/exploits/13853) | `exploit/unix/irc/unreal_ircd_3281_backdoor` |
| Haraka SMTP | < 2.8.9 |  | RCE | [exploit-db](https://www.exploit-db.com/exploits/41162) |   |
| Zabbix | 2.2 < 3.0.3 |  | RCE | [exploit-db](https://www.exploit-db.com/exploits/39937) |   |
| CouchDB | < 2.1.0 | CVE-2017-12636 | RCE | [exploit-db](https://www.exploit-db.com/exploits/44913/) <br> [ref](https://justi.cz/security/2017/11/14/couchdb-rce-npm.html) |   |
| PlaySMS | 1.4 |  | RCE | [exploit-db](https://www.exploit-db.com/exploits/42044) |   |
| ImageMagick  | < 6.9.3-9 <br> released 2016-04-30  | CVE-2016–3714 | RCE | [https://imagetragick.com/](https://imagetragick.com/) |   |
