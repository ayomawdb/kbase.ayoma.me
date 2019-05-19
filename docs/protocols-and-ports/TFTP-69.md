## Enumeration
```
tftp ip_address PUT local_file
tftp ip_address GET conf.txt (or other files)

Solarwinds TFTP server
tftp – i <IP> GET /etc/passwd (old Solaris)
```

## Connect

```
TFTP
tftp> connect
(to) <ip>
tftp> verbose
```

## Transfer file

```
tftp> binary
tftp> put example.exe /windows/system32/example.exe
```

## Receive file

```
tftp> binary
tftp> get /windows/system32/example.exe
```
