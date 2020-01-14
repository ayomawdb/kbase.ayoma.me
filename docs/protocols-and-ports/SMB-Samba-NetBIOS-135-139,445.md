## Server Message Block (SMB) Versions

| SMB Version     | Windows version     |
| :-------------- | :------------------ |
| CIFS | Microsoft Windows NT 4.0 |
| SMB 1.0 | Windows 2000, Windows XP, Windows Server 2003 and Windows Server 2003 R2 |
| SMB 2.0 | Windows Vista & Windows Server 2008 |
| SMB 2.1 | Windows 7 and Windows Server 2008 R2 |
| SMB 3.0 | Windows 8 and Windows Server 2012 |
| SMB 3.0.2 | Windows 8.1 and Windows Server 2012 R2 |
| SMB 3.1.1 | Windows 10 and Windows Server 2016 |


## Ports

netbios-ns `137/tcp` # (NBT over IP) NETBIOS Name Service
netbios-ns `137/udp`

netbios-dgm `138/tcp` # (NBT over IP) NETBIOS Datagram Service
netbios-dgm `138/udp`

netbios-ssn `139/tcp` # (NBT over IP) NETBIOS session service
netbios-ssn `139/udp`

microsoft-ds `445/tcp` # (SMB over IP) If you are using Active Directory (used when SMB is used directly on TCP stack, without using NetBIOS)


## NetBIOS suffixes

For unique names:
```
00: Workstation Service (workstation name)
03: Windows Messenger service
06: Remote Access Service
20: File Service (also called Host Record)
21: Remote Access Service client
1B: Domain Master Browser – Primary Domain Controller for a domain
1D: Master Browser
```

For group names:
```
00: Workstation Service (workgroup/domain name)
1C: Domain Controllers for a domain
1E: Browser Service Elections
```

## Version
```
auxiliary/scanner/smb/smb_version
```

## Brute force
```
auxiliary/scanner/smb/smb_login
```

## User enumerate
```
scanner/smb/smb_lookupsid
```

## Scanning

> - Ref: [https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/](https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/)

### nmap
```
ls -lh /usr/share/nmap/scripts/smb*
```

```
nmap --script safe -p445 $ip
```

```
nmap --script smb-protocols -p445 $ip
```

```
nmap -p 139,446 $ip --open
```

```
nmap ‐v ‐p 139,445 -‐script smb‐*  $ip
nmap ‐v ‐p 139,445 --script vuln $ip
nmap ‐v ‐p 139,445 -‐script smb‐vuln*  $ip
nmap ‐v ‐p 139,445 -‐script smb‐security‐mode  $ip
nmap ‐v ‐p 139,445 -‐script smb‐os-discovery  $ip
nmap ‐v ‐p 139,445 -‐script smb‐check-vulns --script-args=unsafe=1  $ip
```

```
smb-vuln-conficker
smb-vuln-cve2009-3103
smb-vuln-ms06-025
smb-vuln-ms07-029
smb-vuln-regsvc-dos
smb-vuln-ms08-067
```

https://security.stackexchange.com/questions/119827/missing-scripts-in-nmap

### nmblookup

- Query NetBIOS names and map them to IP addresses in a network
- Using NetBIOS over TCP/IP queries

```
nmblookup -A $ip
```

### nbtscan

- Scan NetBIOS name servers open on a local or remote TCP/IP network
- Works on a whole subnet instead of individual IP
- Similar to `nbtstat` (Windows standard tool)

```
nbtscan $ip/24
```

### nbtstat

```
nbtstat $ip
nbtscan -‐r $ip/24
```

- nbtstat -c: displays the contents of the NetBIOS name cache, the table of NetBIOS names and their resolved IP addresses.
- nbtstat -n: displays the names that have been registered locally on the system.
- nbtstat -r: displays the count of all NetBIOS names resolved by broadcast and querying a WINS server.
- nbtstat -R: purges and reloads the remote cache name table.
- nbtstat -RR: sends name release packets to WINs and then starts Refresh.
- nbtstat -s: lists the current NetBIOS sessions and their status, including statistics.
- nbtstat -S: lists sessions table with the destination IP addresses.

### SMBMap - enumerate samba share drives across an entire domain

- Allows users to enumerate samba share drives across an entire domain
- Usage
  - List share drives, drive permissions, share contents
  - Upload/download functionality
  - File name auto-download pattern matching
  - Execute remote commands

```
smbmap -H $ip
```

```
smbmap -u "" -p "" -d <workgroup> -H $ip
smbmap -u <user> -p <password> -d <workgroup> -H $ip
smbmap -u <user> -p <password> -d <workgroup> -H $ip -L  #test command execution
smbmap -u <user> -p <password> -d <workgroup> -H $ip -r  #read drive
```

Recursively list dirs, and files:
```
smbmap -R $sharename -H $ip
```

Search for `Groups.xml` in given share:
```
smbmap -R $shareName -H $ip -A Groups.xml -q
```

Downloads a file in quiet mode:
```
smbmap -R $sharename -H $ip -A $fileyouwanttodownload -q
```

### smbclient

- Client that can "talk" to an SMB/CIFS server
- Operations
  - Upload/download functionality
  - Retrieving directory information
```
smbclient -L \\WIN7\IPC$ -I 192.168.13.218
smbclient \\192.168.13.236\some-share -o user=root,pass=root,workgroup=BOB
```

```
smbclient -L $ip
smbclient -L $ip -U $username -p 445
   password: <prompt>
smbclient -L //server/share
smbclient -L //server/share password options
```

```
smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *
```

Upload file:
```
smbclient //192.168.31.142/ADMIN$ -U "nobody"%"somepassword" -c "put 40280.py"
```

### rpcclient

- Part of the Samba suite
- Developed to test MS-RPC functionality in Samba
- Usable to open an authenticated SMB session to a target machine

NULL session:
```
rpcclient -U "" -N 192.168.1.102
```

User session:
```
rpcclient -U htb\\james mantis.htb.local
```

Querying:
```
rpcclient $> srvinfo
rpcclient $> enum<tab><tab>
rpcclient $> enumdomusers            // Username and RID (suffix of SID)
rpcclient $> queryuser 0x3e8         // Info of the user for given RID
rpcclient $> enumalsgroups domain    // Enum aliases groups
rpcclient $> enumalsgroups builtin
rpcclient $> lookupnames james
```

### Enum4linux

- Tool for enumerating information from Windows and Samba systems
- Wrapper for `smbclient`, `rpcclient`, `net` and `nmblookup`

```
enum4linux -a $ip
enum4linux -U $ip
```

```
- RID cycling (When RestrictAnonymous is set to 1 on Windows 2000)
- User listing (When RestrictAnonymous is set to 0 on Windows 2000)
- Listing of group membership information
- Share enumeration
- Detecting if the host is in a workgroup or a domain
- Identifying the remote operating system
- Password policy retrieval
```

> - Ref: https://hackercool.com/2016/07/smb-enumeration-with-kali-linux-enum4linuxacccheck-smbmap/

### acccheck

- Password attacks

```
acccheck -v -t $ip -u <user> -P <password_file>
```

### mblookup

- NetBIOS over TCP/IP client used to lookup NetBIOS names

## Mount SMB share

```
sudo apt-get install cifs-utils
```
```
mkdir /mnt/$shareName
mount -t cifs //$ip/$shareName /mnt/$shareName -o username=$username,password=$password,domain=$domain

mount -t auto --source //192.168.31.147/kathy --target /tmp/smb/ -o username=root,workgroup=WORKGROUP
```

```
net use X: \\<server>\<sharename> /USER:<domain>\<username> <password> /PERSISTENT:YES
```

## Null Session Enumeration

Null Session Enumeration (enabled by default in SMB1)
```
net use \\192.168.1.1\ipc$ "" /u:""
net view \\ip_address
```

```
rpcclient -U "" ip (give empty password)
  > srvinfo
  > enumdomusers
  > getdompwinfo
```

## Use UpTime to guess patch level

- https://github.com/SpiderLabs/Responder/blob/master/tools/FindSMB2UPTime.py

```
python FindSMB2UpTime.py 172.16.80.10
```

## Enable / Disable / Status

> Detect, enable and disableyeha SMBv1, SMBv2, and SMBv3 in Windows and Windows Server: https://support.microsoft.com/en-gb/help/2696547/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-and

### Windows Server 2012 R2 & 2016: PowerShell methods

#### SMB v1

- Detect: `Get-WindowsFeature FS-SMB1`
- Disable: `Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol`
- Enable: `Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol`

#### SMB v2/v3

- Detect: `Get-SmbServerConfiguration | Select EnableSMB2Protocol`
- Disable: `Set-SmbServerConfiguration -EnableSMB2Protocol $false`
- Enable: `Set-SmbServerConfiguration -EnableSMB2Protocol $true`

### Windows 8.1 and Windows 10: PowerShell method

#### SMB v1 Protocol

- Detect:	`Get-WindowsOptionalFeature –Online –FeatureName SMB1Protocol`
- Disable:	`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`
- Enable:	`Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`

#### SMB v2/v3 Protocol

- Detect:	`Get-SmbServerConfiguration | Select EnableSMB2Protocol`
- Disable: `Set-SmbServerConfiguration –EnableSMB2Protocol $false`
- Enable:	`Set-SmbServerConfiguration –EnableSMB2Protocol $true`

### Windows 8 and Windows Server 2012

#### SMB v1 on SMB Server

- Detect:	`Get-SmbServerConfiguration | Select EnableSMB1Protocol`
- Disable:	`Set-SmbServerConfiguration -EnableSMB1Protocol $false`
- Enable:	`Set-SmbServerConfiguration -EnableSMB1Protocol $true`

#### SMB v2/v3 on SMB Server

- Detect:	`Get-SmbServerConfiguration | Select EnableSMB2Protocol`
- Disable:	`Set-SmbServerConfiguration -EnableSMB2Protocol $false`
- Enable:	`Set-SmbServerConfiguration -EnableSMB2Protocol $true`

###  Windows 7, Windows Server 2008 R2, Windows Vista, and Windows Server 2008

#### SMB v1 on SMB Server

Default configuration = Enabled (No registry key is created), so no SMB1 value will be returned

- Detect: `Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | ForEach-Object {Get-ItemProperty $_.pspath}`
- Disable: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 –Force`
- Enable: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 1 –Force`

#### SMB v2/v3 on SMB Server

- Detect: `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | ForEach-Object {Get-ItemProperty $_.pspath}``
- Disable: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 0 –Force`
- Enable: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 1 –Force`

### Disable SMB Client

#### SMB v1 on SMB Client

- Detect:	`sc.exe qc lanmanworkstation`
- Disable:
```
sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
sc.exe config mrxsmb10 start= disabled
```
- Enable:
```
sc.exe config lanmanworkstation depend= bowser/mrxsmb10/mrxsmb20/nsi
sc.exe config mrxsmb10 start= auto
```

#### SMB v2/v3 on SMB Client

- Detect:	`sc.exe qc lanmanworkstation`
- Disable:
```
sc.exe config lanmanworkstation depend= bowser/mrxsmb10/nsi
sc.exe config mrxsmb20 start= disabled
```
- Enable:
```
sc.exe config lanmanworkstation depend= bowser/mrxsmb10/mrxsmb20/nsi
sc.exe config mrxsmb20 start= auto
```

## Samba Configuration

Configuration file

```
/etc/samba/smb.conf
smb.conf
lmhosts
```

Test & reload configuration

```
testparm -v
service smb restart
```

User creation

```
smbpasswd -a <username>
```

## Samba Enumeration

```
#!/bin/sh

# Author: rewardone
# Description:
#  Requires root or enough permissions to use tcpdump
#  Will listen for the first 7 packets of a null login
#  and grab the SMB Version
# Notes:
#  Will sometimes not capture or will print multiple
#  lines. May need to run a second time for success.

if [ -z $1 ]; then echo "Usage: ./smbver.sh RHOST {RPORT}" && exit; else rhost=$1; fi
if [ ! -z $2 ]; then rport=$2; else rport=139; fi

tcpdump -s0 -n -i tap0 src $rhost and port $rport -A -c 7 2>/dev/null | grep -i "samba\|s.a.m" | tr -d '.' | grep -oP 'UnixSamba.*[0-9a-z]' | tr -d '\n' & echo -n "$rhost: " &

echo "exit" | smbclient -L $rhost 1>/dev/null 2>/dev/null
echo "" && sleep .1
```

## Pending Tools

- SuperScan
- Hyena
- Winfingerprint
- NetBIOS enumerator

## NetBios

https://dzone.com/articles/practical-fun-with-netbios-name-service-and-comput
https://dzone.com/articles/fun-with-netbios-name-service-and-computer-browser

## References

- https://www.youtube.com/watch?v=jUc1J31DNdw&t=445s
- [Implementing CIFS - The Common Internet Filesystem - http://www.ubiqx.org/cifs/](http://www.ubiqx.org/cifs/)
- [Using Samba 2nd Edition - http://www.samba.org/samba/docs/using_samba/toc.html](http://www.samba.org/samba/docs/using_samba/toc.html)

## Vulnerabilities

- Linux
  -  CVE-2007-2447 - Samba versions 3.0.20 through 3.0.25rc3
    - When the "username map script" smb.conf option is enabled
    - https://github.com/amriunix/cve-2007-2447
    - `exploit/windows/smb/ms08_067_netapi`
- Windows
  - CVE-2008-4250 MS08-067 - Microsoft Server Service Relative Path Stack Corruption
    - Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2, Vista Gold and SP1, Server 2008, and 7 Pre-Beta
    - https://github.com/jivoi/pentest/blob/master/exploit_win/ms08-067.py
    - https://vulners.com/exploitdb/EDB-ID:6824
    - `exploit/windows/smb/ms08_067_netapi`
