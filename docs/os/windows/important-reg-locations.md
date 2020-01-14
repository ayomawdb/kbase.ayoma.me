# Important Registry Locations

- Installed programs: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
- Gain system shell at login using 5x[shift]:

  - `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe` with property `Debugger` set to `cmd.exe`
  - `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe` with property `Debugger` set to `cmd.exe`
  - Disable macro security:

- Enable EDP: `reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`

## Ways to access registry

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

## Tasks

- Recently used commands
- Installed apps
- Turn off network level auth
- Attach debugger to setg.exe
