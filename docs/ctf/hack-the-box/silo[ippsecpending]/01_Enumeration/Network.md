## TCP
```
# Nmap 7.70 scan initiated Wed Apr 24 07:09:09 2019 as: nmap -sV -sC -oA nmap --script safe -T4 10.10.10.82
Pre-scan script results:
| broadcast-dhcp-discover:
|   Response 1 of 1:
|     IP Offered: 10.0.2.16
|     Subnet Mask: 255.255.255.0
|     Router: 10.0.2.2
|     Domain Name Server: 10.0.2.3
|_    Server Identifier: 10.0.2.2
|_eap-info: please specify an interface with -e
| targets-asn:
|_  targets-asn.asn is a mandatory parameter
Nmap scan report for 10.10.10.82 (10.10.10.82)
Host is up (0.15s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
| http-comments-displayer:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.82
|     
|     Path: http://10.10.10.82:80/
|     Line number: 7
|     Comment:
|         <!--
|         body {
|         	color:#000000;
|         	background-color:#0072C6;
|         	margin:0;
|         }
|         
|         #container {
|         	margin-left:auto;
|         	margin-right:auto;
|         	text-align:center;
|         	}
|         
|         a img {
|         	border:none;
|         }
|         
|_        -->
|_http-date: Wed, 24 Apr 2019 11:10:45 GMT; -1m29s from local time.
|_http-fetch: Please enter the complete path of the directory to save data in.
| http-headers:
|   Content-Length: 701
|   Content-Type: text/html
|   Last-Modified: Wed, 03 Jan 2018 00:36:17 GMT
|   Accept-Ranges: bytes
|   ETag: "1114bde2a84d31:0"
|   Server: Microsoft-IIS/8.5
|   X-Powered-By: ASP.NET
|   Date: Wed, 24 Apr 2019 11:10:45 GMT
|   Connection: close
|   
|_  (Request type: HEAD)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-mobileversion-checker: No mobile version detected.
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_http-security-headers:
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
| http-useragent-tester:
|   Status for browser useragent: 200
|   Allowed User Agents:
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
|_http-xssed: No previously reported XSS vuln.
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
|_unusual-port: oracle-tns unexpected on port tcp/1521
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49161/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1m28s, deviation: 0s, median: -1m28s
| dns-blacklist:
|   SPAM
|_    all.spamrats.com - FAIL
|_fcrdns: FAIL (No A record)
|_ipidseq: Unknown
|_msrpc-enum: No accounts left to try
|_path-mtu: PMTU == 1500
| qscan:
| PORT   FAMILY  MEAN (us)  STDDEV    LOSS (%)
| 1      0       215971.50  42529.14  0.0%
| 80     0       191252.50  41690.66  0.0%
| 135    0       188452.30  37772.99  0.0%
| 139    0       195588.60  38836.83  0.0%
| 445    0       191105.30  40361.52  0.0%
| 1521   0       192247.10  41941.94  0.0%
| 49152  0       186131.00  35036.00  0.0%
| 49153  0       215171.70  47084.34  0.0%
|_49154  0       193628.90  40600.77  0.0%
| smb-mbenum:
|_  ERROR: Failed to connect to browser service: No accounts left to try
| smb-protocols:
|   dialects:
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2.02
|     2.10
|     3.00
|_    3.02
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-capabilities:
|   2.02:
|     Distributed File System
|   2.10:
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3.00:
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3.02:
|     Distributed File System
|     Leasing
|_    Multi-credit operations
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-04-24 07:10:44
|_  start_date: 2019-04-22 01:23:56

Post-scan script results:
| reverse-index:
|   80/tcp: 10.10.10.82
|   135/tcp: 10.10.10.82
|   139/tcp: 10.10.10.82
|   445/tcp: 10.10.10.82
|   1521/tcp: 10.10.10.82
|   49152/tcp: 10.10.10.82
|   49153/tcp: 10.10.10.82
|   49154/tcp: 10.10.10.82
|   49155/tcp: 10.10.10.82
|   49158/tcp: 10.10.10.82
|   49160/tcp: 10.10.10.82
|_  49161/tcp: 10.10.10.82
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Apr 24 07:14:07 2019 -- 1 IP address (1 host up) scanned in 298.36 seconds

```
## UDP
