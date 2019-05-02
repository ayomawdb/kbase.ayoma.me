## TCP 

```
nmap -sV -sC -oA nmap --script safe -T4 10.10.10.95
Starting Nmap 7.70 ( https://nmap.org ) at 2019-04-24 02:21 EDT
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
Nmap scan report for 10.10.10.95
Host is up (0.23s latency).
Not shown: 999 filtered ports
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
| http-auth-finder: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.95
|   url                                        method
|   http://10.10.10.95:8080/manager/status     HTTP: Basic
|   http://10.10.10.95:8080/host-manager/html  HTTP: Basic
|_  http://10.10.10.95:8080/manager/html       HTTP: Basic
|_http-date: Wed, 24 Apr 2019 13:21:10 GMT; +6h58m31s from local time.
|_http-favicon: Apache Tomcat
|_http-fetch: Please enter the complete path of the directory to save data in.
| http-grep: 
|   (1) http://10.10.10.95:8080/docs/appdev/: 
|     (1) email: 
|_      + craigmcc@apache.org
| http-headers: 
|   Server: Apache-Coyote/1.1
|   Content-Type: text/html;charset=ISO-8859-1
|   Transfer-Encoding: chunked
|   Date: Wed, 24 Apr 2019 13:21:12 GMT
|   Connection: close
|   
|_  (Request type: HEAD)
|_http-mobileversion-checker: No mobile version detected.
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_http-security-headers: 
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
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

Host script results:
|_clock-skew: mean: 6h58m30s, deviation: 0s, median: 6h58m30s
|_fcrdns: FAIL (No PTR record)
|_ipidseq: Random Positive Increments
|_path-mtu: PMTU == 1500

Post-scan script results:
| reverse-index: 
|_  8080/tcp: 10.10.10.95
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 233.82 seconds
```



## UDP



