## TCP
```
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
Nmap scan report for 10.10.10.60 (10.10.10.60)
Host is up (0.28s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE    VERSION
80/tcp  open  http       lighttpd 1.4.35
|_http-comments-displayer: Couldn't find any comments.
|_http-date: Fri, 26 Apr 2019 10:47:48 GMT; +20m49s from local time.
|_http-fetch: Please enter the complete path of the directory to save data in.
| http-headers:
|   Location: https://10.10.10.60/
|   Content-Length: 0
|   Connection: close
|   Date: Fri, 26 Apr 2019 10:47:59 GMT
|   Server: lighttpd/1.4.35
|   
|_  (Request type: GET)
|_http-mobileversion-checker: No mobile version detected.
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_http-security-headers:
|_http-server-header: lighttpd/1.4.35
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
|_http-title: Did not follow redirect to https://10.10.10.60/
| http-useragent-tester:
|   Status for browser useragent: false
|   Redirected To: https://10.10.10.60/
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
443/tcp open  ssl/https?
|_http-comments-displayer: Couldn't find any comments.
|_http-fetch: Please enter the complete path of the directory to save data in.
|_http-mobileversion-checker: No mobile version detected.
|_http-referer-checker: Couldn't find any cross-domain scripts.
| http-security-headers:
|   Strict_Transport_Security:
|_    HSTS not configured in HTTPS Server
| http-useragent-tester:
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
| ssl-ccs-injection:
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       http://www.cvedetails.com/cve/2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|_ssl-date: TLS randomness does not represent time
| ssl-dh-params:
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
|             Modulus Type: Non-safe prime
|             Modulus Source: RFC5114/1024-bit DSA group with 160-bit prime order subgroup
|             Modulus Length: 1024
|             Generator Length: 1024
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle:
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  CVE:CVE-2014-3566  OSVDB:113251
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
|     References:
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|       http://osvdb.org/113251
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|_      https://www.imperialviolet.org/2014/10/14/poodle.html

Host script results:
|_clock-skew: mean: 20m48s, deviation: 0s, median: 20m48s
| dns-blacklist:
|   PROXY
|     http.dnsbl.sorbs.net - FAIL
|_    tor.dan.me.uk - FAIL
|_fcrdns: FAIL (No A record)
|_ipidseq: Randomized
|_path-mtu: PMTU == 1500
| qscan:
| PORT  FAMILY  MEAN (us)  STDDEV    LOSS (%)
| 80    0       276805.67  43071.59  10.0%
|_443   0       274113.20  42161.88  0.0%

Post-scan script results:
| reverse-index:
|   80/tcp: 10.10.10.60
|_  443/tcp: 10.10.10.60
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 413.68 seconds
root@kali:~/HTB/sense#

```

## UDP
