## Crack Linux Hash
```
unshadow passwd.txt shadow.txt > hashes.txt
john —wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

## Cisco hashes
```
python3 cisco_pwdecrypt.py -u "\$1\$pdQG\$o8nrSzsGXeaduXrjlvKc91" -d /usr/share/wordlists/rockyou.txt
```

## Base64 encoding example:
```
ZENvZGU=
to decode string into png: nano encoded.txt | base64 —decode > out.png OR https://onlinepngtools.com/convert-base64-to-png
to decode string to string: echo `echo <base64string> | base64 —decode`
```

## Base32 encoding example:
```
MRBW6ZDFEBBGC43FGMZA====
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

## Encrypted Disk or .img?
```
binwalk -e
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

## Ceaser decode
```
echo "string" | tr '[A-Za-z]' '[N-ZA-Mn-za-m]'
```
