## TCP
```
roadcast-dhcp-discover:
|   Response 1 of 1:
|     IP Offered: 10.0.2.16
|     Subnet Mask: 255.255.255.0
|     Router: 10.0.2.2
|     Domain Name Server: 10.0.2.3
|_    Server Identifier: 10.0.2.2
|_eap-info: please specify an interface with -e
| targets-asn:
|_  targets-asn.asn is a mandatory parameter
Nmap scan report for 10.10.10.68 (10.10.10.68)
Host is up (0.16s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-date: Wed, 24 Apr 2019 09:38:25 GMT; -1m28s from local time.
|_http-fetch: Please enter the complete path of the directory to save data in.
| http-grep:
|   (1) http://10.10.10.68:80/js/this.src;:
|     (1) ip:
|_      + 10.10.10.68
| http-headers:
|   Date: Wed, 24 Apr 2019 09:38:28 GMT
|   Server: Apache/2.4.18 (Ubuntu)
|   Last-Modified: Mon, 04 Dec 2017 23:03:42 GMT
|   ETag: "1e3f-55f8bbac32f80"
|   Accept-Ranges: bytes
|   Content-Length: 7743
|   Vary: Accept-Encoding
|   Connection: close
|   Content-Type: text/html
|   
|_  (Request type: HEAD)
| http-internal-ip-disclosure:
|_  Internal IP Leaked: 127.0.1.1
|_http-mobileversion-checker: No mobile version detected.
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_http-security-headers:
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-slowloris-check:
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-title: Arrexel's Development Site
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
|_clock-skew: mean: -1m28s, deviation: 0s, median: -1m28s
|_fcrdns: FAIL (No A record)
|_ipidseq: All zeros
|_path-mtu: PMTU == 1500
| qscan:
| PORT  FAMILY  MEAN (us)  STDDEV    LOSS (%)
| 1     0       203573.20  47138.34  0.0%
|_80    0       199510.40  44353.09  0.0%

Post-scan script results:
| reverse-index:
|_  80/tcp: 10.10.10.68
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 379.90 seconds

```

## UDP
