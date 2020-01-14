## Cheatsheets 
-  [https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf](https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf)
## General Commands 
| | |
| -- | -- |
| Listen on port 567/TCP | `nc -l -p 567` |
| Connecting to 567 of 1.2.3.4 | `nc 1.2.3.4 5676` |
| Pipe a text file to the listener | `cat infile | nc 1.2.3.4 567 -q 10` |
| Have the listener save a received text file | `nc -l -p 567 > textfile` |
| Transfer a directory | Reciever: `nc -l -p 678 | tar xvfpz` <br/>Sender: `tar zcfp - /path/to/directory | nc -w 3 1.2.3.4 678`  |
| Send a message to your syslog server (the <0> means emerg) | `echo '<0>message' | nc -w 1 -u syslogger 514` |
| Setup a remote shell listener | `nc -v -e '/bin/bash' -l -p 1234 -t` or `nc l p 1234 e "c:\windows\system32\cmd.exe"` |
| Make an HTTP request | `echo -e "GET http://www.google.com HTTP/1.0nn" | nc -w 5 www.google.com 80` |
| One-page webserver | `cat homepage.txt | nc -v -l -p 80` |

## General Options 

| | |
| -- | -- |
| Use IPv4 addressing only | `nc -4 [options] [host] [port]` |
| Use IPv6 addressing only | `nc -6 [options] [host] [port]` |
| UDP instead of TCP | `nc -u [options] [host] [port]` |
| Listen for an incoming connection | `nc -l [host] [port]` |
| Continue listening after client has disconnected | `nc -k -l [host] [port]` |
| No DNS lookups | `nc -n [host] [port]` |
| Use specific source port | `nc -p [source port] [host] [port]` |
| Use source IP | `nc -s [source ip] [host] [port]` |
| Apply 'n' second timeout | `nc -w [timeout] [host] [port]` |
| Verbose output | `nc -v [host] [port]` |

## Port Scanning 

| | |
| -- | -- |
| Scan a single TCP port | `nc -zv hostname.com 80` |
| Scan a range of ports | `nc -zv hostname.com 80-84` |
| Scan multiple ports | `nc -zv hostname.com 80 84` |

## Other 

One page web server
```
while : ; do ( echo -ne "HTTP/1.1 200 OK\r\nContent-Length: $(wc -c <index.html)\r\n\r\n" ; cat index.html; ) | nc -l -p 8080 ; done
```

Proxy
```
mknod backpipe p ; nc -l [proxy port] < backpipe | nc [destination host] [destination port] > pipe
```

> [https://kapeli.com/cheat_sheets/Netcat.docset/Contents/Resources/Documents/index](https://kapeli.com/cheat_sheets/Netcat.docset/Contents/Resources/Documents/index)
>
> [http://workrobot.com/sysadmin/security/netcat_cheatsheet.html](http://workrobot.com/sysadmin/security/netcat_cheatsheet.html)

Wrap readline history library (support up arrow, etc)

```
rlwrap nc -t remotehost 23
```

