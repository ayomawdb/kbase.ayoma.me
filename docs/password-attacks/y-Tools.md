# Tools

## Word-lists

- CeWL - Custom Word List Generator: [https://github.com/digininja/CeWL](https://github.com/digininja/CeWL)

## Password Spraying

- Spray: [https://github.com/SpiderLabs/Spray](https://github.com/SpiderLabs/Spray)
- Password spraying using AWS Lambda for IP rotation: [https://github.com/ustayready/CredKing](https://github.com/ustayready/CredKing)

## Brute-forcing

- Patator - multi-purpose brute-forcer: [https://github.com/lanjelot/patator](https://github.com/lanjelot/patator)

```
* ftp_login      : Brute-force FTP
* ssh_login      : Brute-force SSH
* telnet_login   : Brute-force Telnet
* smtp_login     : Brute-force SMTP
* smtp_vrfy      : Enumerate valid users using the SMTP VRFY command
* smtp_rcpt      : Enumerate valid users using the SMTP RCPT TO command
* finger_lookup  : Enumerate valid users using Finger
* http_fuzz      : Brute-force HTTP/HTTPS
* rdp_gateway    : Brute-force RDP Gateway
* ajp_fuzz       : Brute-force AJP
* pop_login      : Brute-force POP
* pop_passd      : Brute-force poppassd (not POP3)
* imap_login     : Brute-force IMAP
* ldap_login     : Brute-force LDAP
* smb_login      : Brute-force SMB
* smb_lookupsid  : Brute-force SMB SID-lookup
* rlogin_login   : Brute-force rlogin
* vmauthd_login  : Brute-force VMware Authentication Daemon
* mssql_login    : Brute-force MSSQL
* oracle_login   : Brute-force Oracle
* mysql_login    : Brute-force MySQL
* mysql_query    : Brute-force MySQL queries
* rdp_login      : Brute-force RDP (NLA)
* pgsql_login    : Brute-force PostgreSQL
* vnc_login      : Brute-force VNC
* dns_forward    : Brute-force DNS
* dns_reverse    : Brute-force DNS (reverse lookup subnets)
* ike_enum       : Enumerate IKE transforms
* snmp_login     : Brute-force SNMPv1/2 and SNMPv3
* unzip_pass     : Brute-force the password of encrypted ZIP files
* keystore_pass  : Brute-force the password of Java keystore files
* sqlcipher_pass : Brute-force the password of SQLCipher-encrypted databases
* umbraco_crack  : Crack Umbraco HMAC-SHA1 password hashes
```

```
patator http_fuzz url=http://example.com/index.php method=POST
body=​ 'name=zapper&password=FILE0&autologin=1&enter=Sign+in'
0=/usr/share/SecLists/Passwords/darkweb2017-top1000.txt accept_cookie=1 follow=1
-x ignore:fgrep=​ 'Login name or password is incorrect.'
```

- Hydra - [https://github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra)

```
Asterisk, AFP, Cisco AAA, Cisco auth, Cisco enable, CVS, Firebird, FTP,
HTTP-FORM-GET, HTTP-FORM-POST, HTTP-GET, HTTP-HEAD, HTTP-POST, HTTP-PROXY,
HTTPS-FORM-GET, HTTPS-FORM-POST, HTTPS-GET, HTTPS-HEAD, HTTPS-POST, HTTP-Proxy,
ICQ, IMAP, IRC, LDAP, MEMCACHED, MONGODB, MS-SQL, MYSQL, NCP, NNTP,
Oracle Listener, Oracle SID, Oracle, PC-Anywhere, PCNFS, POP3, POSTGRES, RDP,
Rexec, Rlogin, Rsh, RTSP, SAP/R3, SIP, SMB, SMTP, SMTP Enum, SNMP v1+v2+v3,
SOCKS5, SSH (v1 and v2), SSHKEY, Subversion, Teamspeak (TS2), Telnet,
VMware-Auth, VNC and XMPP
```

- Medusa - [https://github.com/jmk-foofus/medusa](https://github.com/jmk-foofus/medusa)

```
AFP, CVS, FTP, HTTP, IMAP, MS-SQL, MySQL, NetWare NCP, NNTP, PcAnywhere, POP3,
PostgreSQL, REXEC, RDP, RLOGIN, RSH, SMBNT, SMTP-AUTH, SMTP-VRFY, SNMP, SSHv2,
Subversion (SVN), Telnet, VMware Authentication Daemon (vmauthd), VNC,
Generic Wrapper, Web Form
```

- ncrack - [https://github.com/nmap/ncrack](https://github.com/nmap/ncrack)

```
SSH, RDP, FTP, Telnet, HTTP(S), Wordpress, POP3(S), IMAP, CVS, SMB, VNC, SIP,
Redis, PostgreSQL, MySQL, MSSQL, MongoDB, Cassandra, WinRM, OWA, DICOM.
```

- [zip] fcrackzip - [https://github.com/hyc/fcrackzip](https://github.com/hyc/fcrackzip)

```
fcrackzip -D -p wordlist.txt -u test.zip
```

## Generators
- Common password pattern generator using strings list: [https://github.com/localh0t/m4ngl3m3](https://github.com/localh0t/m4ngl3m3)
- A script for generating custom passphrase lists to be used for password cracking with hashcat rules: [https://github.com/dafthack/PassphraseGen](https://github.com/dafthack/PassphraseGen)
