- NIST 800-53r4 
  - CA-7 (1-3)
  - CA-8 (2)
- Silent Trinity / gcap 

![](_assets/2020-05-14-22-45-27.png)
![](_assets/2020-05-14-22-46-52.png)

## Red Team

- Do not use standard signatures (file names)
- Change name of the tools (mimidogz) caused endpoint protection tools to fail
- BadBlood

### Responder

![](_assets/2020-05-14-22-50-46.png)
![](_assets/2020-05-14-22-54-13.png)

- Poisoning tool for Windows Default Protocols 
- Detectable using Respounder / Responder Guard 
- 
![](_assets/2020-05-14-22-54-37.png)
![](_assets/2020-05-14-22-55-30.png)
![](_assets/2020-05-14-22-56-29.png)

### CrackMapExec

![](_assets/2020-05-14-22-56-46.png)
![](_assets/2020-05-14-22-57-56.png)

- CrackMap uses DCSync 

Detecting PTH attacks:
![](_assets/2020-05-14-22-58-51.png)
![](_assets/2020-05-14-22-59-48.png)

### DomainPasswordSpray

![](_assets/2020-05-14-23-01-16.png)
![](_assets/2020-05-14-23-02-08.png)
![](_assets/2020-05-14-23-08-50.png)

### Mimikatz 

![](_assets/2020-05-14-23-10-37.png)
![](_assets/2020-05-14-23-12-33.png)

### BloodHound / PlumHound

## Blue team 

- Exchange and outlook do not log.
- IIS log only to disk, not to event log.
- Managed Service Providers (MSP) should see AV kills.
- MSSP should catch Mimikatz.
- BloodHound -> PlumHound

## Setup 

- Run <https://github.com/davidprowe/BadBlood>
- Run <https://github.com/DefensiveOrigins/APT06202001/tree/master/Lab-DomainBuildScripts>
- <https://github.com/DefensiveOrigins/APT06202001/tree/master/Lab-Sysmon/sysmon-modular-master>
  - `Import-Module Merge-SysmonXML.ps1`
  - `Merge-AllSysmonXml -Path ( Get-ChildItem '[0-9]*\*.xml') -AsString | Out-File sysmonconfig.xml`
- Endpoint-protection vs aEDR

## Tooling 

- Collaboration
  - <https://vectr.io/>
  - <https://plextrac.com/>