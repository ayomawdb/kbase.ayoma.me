# Tools

- Patch Extractor : [https://gist.github.com/moshekaplan/e8d16ed91dc3ca53e73145ba3b2baebd](https://gist.github.com/moshekaplan/e8d16ed91dc3ca53e73145ba3b2baebd) [https://gist.github.com/anonymous/d55f494982c0097111d3263cf7099c9d](https://gist.github.com/anonymous/d55f494982c0097111d3263cf7099c9d)

## ntdsXtract

Active Directory forensic framework

-​ https://github.com/csababarta/ntdsxtract

Extract users from ESE DB export:
```
dsusers.py kotarak.dit.export/datatable.3 kotarak.dit.export/link_table.5 hashdump --syshive
kotarak.bin --passwordhashes --lmoutfile lmout.txt --ntoutfile ntout.txt --pwdformat ophc
```

Practice:
- HTB: Kotarak

## LibEseDB

libesedb is a library to access the Extensible Storage Engine (ESE) Database File (EDB) format.

The ESE database format is used in may different applications like Windows Search, Windows Mail, Exchange, Active Directory, etc.

- https://github.com/libyal/libesedb

Dump tables:
```
esedbexport -m tables 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit  
```

Practice:
- HTB: Kotarak

## WinEXE
Winexe remotely executes commands on Windows NT/2000/XP/2003 systems from GNU/Linux (and possibly also from other Unices capable of building the Samba 4 software package).-

- https://sourceforge.net/projects/winexe/

## PowerUpSQL

- Dumping Active Directory Domain Info – with PowerUpSQL!: https://blog.netspi.com/dumping-active-directory-domain-info-with-powerupsql/

## Bloodhound

BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify.

- GitHub: https://github.com/BloodHoundAD/BloodHound

Find where domain admins are logged in:
```
python http://bloodhound.py  -u <USERNAME> -p <PASSWORD> -d <DOMAIN_NAME> -dc <DOMAIN_CONTROLLER_HOSTNAME>
neo4j start
bloodhound
```

## Mimkatz

- Mimikatz 2.0 - Golden Ticket Walkthrough: https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Golden_Ticket_Walkthrough.html

### DCSync

> https://adsecurity.org/?p=1729

```
mimikatz “lsadump::dcsync /domain:rd.adsecurity.org /user:krbtgt”
mimikatz “lsadump::dcsync /domain:rd.adsecurity.org /user:Administrator”
```

“impersonates” a Domain Controller and requests account password data from the targeted Domain Controller.

Required Permissions: Any member of `Administrators`, `Domain Admins`, or `Enterprise Admins` as well as `Domain Controller` computer accounts. Read-Only Domain Controllers are not allowed to pull password data for users by default.

* Prior to DCSync was to run Mimikatz or Invoke-Mimikatz on a Domain Controller to get the `KRBTGT password hash` to create `Golden Tickets`
* With DCSync, the attacker can pull the password hash, as well as previous password hashes, from a Domain Controller over the network without requiring interactive logon or copying off the Active Directory database file (ntds.dit).

Internals:
* Discovers Domain Controller in the specified domain name.
* Requests the Domain Controller replicate the user credentials via [GetNCChanges](https://wiki.samba.org/index.php/DRSUAPI) (leveraging Directory Replication Service (DRS) Remote Protocol)

```
“The client DC sends a DSGetNCChanges request to the server when the first one wants to get AD objects updates from the second one. The response contains a set of updates that the client has to apply to its NC replica.

It is possible that the set of updates is too large for only one response message. In those cases, multiple DSGetNCChanges requests and responses are done. This process is called replication cycle or simply cycle.”

“When a DC receives a DSReplicaSync Request, then for each DC that it replicates from (stored in RepsFrom data structure) it performs a replication cycle where it behaves like a client and makes DSGetNCChanges requests to that DC. So it gets up-to-date AD objects from each of the DC’s which it replicates from.”
```

## Sys Internals

> https://technet.microsoft.com/en-in/sysinternals/bb545021.aspx

- `PsExec` - Execute processes on remote machine
- `PsFile` - Displays list of files opened remotely.
- `PsGetSid` - Translate SID to display name and vice versa
- `PsKill` - Kill processes on local or remote machine
- `PsInfo` - Displays installation, install date, kernel build, physical memory, processors type and number, etc.
- `PsList` - Displays process, CPU, Memory, thread statistics
- `PsLoggedOn` - Displays local and remote logged users
- `PsLogList` - View Event logs

## localrecon.cmd

Utility to generate a summary of a Windows system

https://github.com/bitsadmin/miscellaneous/blob/master/localrecon.cmd

## Other 

- BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment: [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)
- Empire is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent: [https://github.com/EmpireProject/Empire](https://github.com/EmpireProject/Empire)
- A little toolbox to play with Microsoft Kerberos in C: [https://github.com/gentilkiwi/kekeo/](https://github.com/gentilkiwi/kekeo/)
- A little tool to play with Windows security: [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)
- C# toolset for raw Kerberos interaction and abuses: [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- C# project that performs a number of security oriented host-survey "safety checks": [https://github.com/GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt)