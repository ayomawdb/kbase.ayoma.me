## Simple Network Management Protocol (SNMP)

- Baed on UDP - Can be suspectable for IP spoofing and replay
- 1,2,2c versions are plain text
- Week auth and default community strings (public, default)

Devices often support configuration file read and write through private SNMP community string access. Hence having access to private string means router configuration can be altered.

## Configuration Files
```
snmp.conf
snmpd.conf
snmp-config.xml
```

## SNMP - Management Information Base (MBI)

Tree database related to network management.
http://publib.boulder.ibm.com/infocenter/pseries/v5r3/index.jsp?topic=/com.ibm.aix.progcomm/doc/progcomc/mib.htm

commuity strings - public / private / manager / ...

## Scanning
```
nmap -sU -p 161 --open <ip>
nmap -sU -p 161 --script=*snmp* 192.168.1.200
xprobe2 -v -p udp:161:open 192.168.1.200
```
Scan one community string for multiple IPs
```
onesixtyone -c community.txt -i ips.txt
```

```
auxiliary/scanner/snmp/snmp_login
auxiliary/scanner/snmp/snmp_enum
```

## SNMPWalk
```
snmpwalk -Os -c public -v 1 <ip>
```

## Probe MBI
```
snmpwalk -c public -v 1 <ip> 1.3.6.1.2.1.25.4.2.1.2
 • 1.3.6.1.2.1.25.1.6.0 System Processes
 • 1.3.6.1.2.1.25.4.2.1.2 Running Programs
 • 1.3.6.1.2.1.25.4.2.1.4 Processes Path
 • 1.3.6.1.2.1.25.2.3.1.4 Storage Units
 • 1.3.6.1.2.1.25.6.3.1.2 Software Name
 • 1.3.6.1.4.1.77.1.2.25 User Accounts
 • 1.3.6.1.2.1.6.13.1.3	 TCP Local Ports
```

## Default community strings
```
public
private
cisco
  cable-docsis
  ILMI
```

## Important properties
Windows NT
```
.1.3.6.1.2.1.1.5 Hostnames
.1.3.6.1.2.1.4.34.1.5.2.16 IPv6 Address

.1.3.6.1.4.1.77.1.4.2 Domain Name
.1.3.6.1.4.1.77.1.2.25 Usernames
.1.3.6.1.4.1.77.1.2.3.1.1 Running Services
.1.3.6.1.4.1.77.1.2.27 Share Information
```

## Tools

### snmpenum
```
perl snmpenum.pl 192.168.38.200 public windows.txt
```

### snmpwalk
```
snmpwalk -c public 192.168.38.200 -v 1
```

- OpUtils
- SolarWinds
- SNScan
- SNMP Scanner
- NS Auditor
- snmpcheck
- onesixtyone
  - Scan one community string for multiple IPs

```
snmp-check 192.168.1.2 -c public
snmpget -v 1 -c public IP
snmpbulkwalk -v2c -c public -Cn0 -Cr10 IP
```
