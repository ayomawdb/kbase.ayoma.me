## TCP
```
nmap -sV -sC -oA nmap --script safe -T4 10.10.10.150
Starting Nmap 7.70 ( https://nmap.org ) at 2019-04-26 13:28 EDT
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
Nmap scan report for 10.10.10.150
Host is up (0.30s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
|_banner: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4
| ssh-hostkey:
|   2048 8a:d1:69:b4:90:20:3e:a7:b6:54:01:eb:68:30:3a:ca (RSA)
|   256 9f:0b:c2:b2:0b:ad:8f:a1:4e:0b:f6:33:79:ef:fb:43 (ECDSA)
|_  256 c1:2a:35:44:30:0c:5b:56:6a:3f:a5:cc:64:66:d9:a9 (ED25519)
| ssh2-enum-algos:
|   kex_algorithms: (10)
|   server_host_key_algorithms: (5)
|   encryption_algorithms: (6)
|   mac_algorithms: (10)
|_  compression_algorithms: (2)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-auth-finder:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.150
|   url                                                                              method
|   http://10.10.10.150:80/                                                          FORM
|   http://10.10.10.150:80/index.php/2-uncategorised/1-first-post-of-curling2018     FORM
|   http://10.10.10.150:80/index.php/component/users/?view=remind&amp;Itemid=101     FORM
|   http://10.10.10.150:80/index.php/2-uncategorised/3-what-s-the-object-of-curling  FORM
|   http://10.10.10.150:80/index.php/component/users/?view=reset&amp;Itemid=101      FORM
|_  http://10.10.10.150:80/index.php/2-uncategorised/2-curling-you-know-its-true     FORM
| http-backup-finder:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.150
|   http://10.10.10.150:80/index.php/2-uncategorised/index.bak
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/1-first-post-of-curling2018~
|   http://10.10.10.150:80/index.php/2-uncategorised/index copy.php/2-uncategorised/1-first-post-of-curling2018
|   http://10.10.10.150:80/index.php/2-uncategorised/Copy of index.php/2-uncategorised/1-first-post-of-curling2018
|   http://10.10.10.150:80/index.php/2-uncategorised/Copy (2) of index.php/2-uncategorised/1-first-post-of-curling2018
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/1-first-post-of-curling2018.1
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/1-first-post-of-curling2018.~1~
|   http://10.10.10.150:80/index.php/2-uncategorised/index.bak
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/1-first-post-of-curling2018~
|   http://10.10.10.150:80/index.php/2-uncategorised/index copy.php/2-uncategorised/1-first-post-of-curling2018
|   http://10.10.10.150:80/index.php/2-uncategorised/Copy of index.php/2-uncategorised/1-first-post-of-curling2018
|   http://10.10.10.150:80/index.php/2-uncategorised/Copy (2) of index.php/2-uncategorised/1-first-post-of-curling2018
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/1-first-post-of-curling2018.1
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/1-first-post-of-curling2018.~1~
|   http://10.10.10.150:80/index.php/2-uncategorised/index.bak
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/3-what-s-the-object-of-curling~
|   http://10.10.10.150:80/index.php/2-uncategorised/index copy.php/2-uncategorised/3-what-s-the-object-of-curling
|   http://10.10.10.150:80/index.php/2-uncategorised/Copy of index.php/2-uncategorised/3-what-s-the-object-of-curling
|   http://10.10.10.150:80/index.php/2-uncategorised/Copy (2) of index.php/2-uncategorised/3-what-s-the-object-of-curling
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/3-what-s-the-object-of-curling.1
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/3-what-s-the-object-of-curling.~1~
|   http://10.10.10.150:80/index.php/2-uncategorised/index.bak
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/3-what-s-the-object-of-curling~
|   http://10.10.10.150:80/index.php/2-uncategorised/index copy.php/2-uncategorised/3-what-s-the-object-of-curling
|   http://10.10.10.150:80/index.php/2-uncategorised/Copy of index.php/2-uncategorised/3-what-s-the-object-of-curling
|   http://10.10.10.150:80/index.php/2-uncategorised/Copy (2) of index.php/2-uncategorised/3-what-s-the-object-of-curling
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/3-what-s-the-object-of-curling.1
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/3-what-s-the-object-of-curling.~1~
|   http://10.10.10.150:80/index.php/2-uncategorised/index.bak
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/2-curling-you-know-its-true~
|   http://10.10.10.150:80/index.php/2-uncategorised/index copy.php/2-uncategorised/2-curling-you-know-its-true
|   http://10.10.10.150:80/index.php/2-uncategorised/Copy of index.php/2-uncategorised/2-curling-you-know-its-true
|   http://10.10.10.150:80/index.php/2-uncategorised/Copy (2) of index.php/2-uncategorised/2-curling-you-know-its-true
|   http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/2-curling-you-know-its-true.1
|_  http://10.10.10.150:80/index.php/2-uncategorised/index.php/2-uncategorised/2-curling-you-know-its-true.~1~
| http-comments-displayer:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.150
|     
|     Path: http://10.10.10.150:80/index.php/2-uncategorised/2-curling-you-know-its-true
|     Line number: 55
|     Comment:
|         <!-- Begin Content -->
|     
|     Path: http://10.10.10.150:80/media/system/js/caption.js?4c6b364068a1c45e7cd3bb9b6a49b052
|     Line number: 1
|     Comment:
|         /*
|                 GNU General Public License version 2 or later; see LICENSE.txt
|         */
|     
|     Path: http://10.10.10.150:80/index.php/2-uncategorised/2-curling-you-know-its-true
|     Line number: 217
|     Comment:
|         <!-- End Right Sidebar -->
|     
|     Path: http://10.10.10.150:80/index.php/2-uncategorised/2-curling-you-know-its-true
|     Line number: 42
|     Comment:
|         <!-- Header -->
|     
|     Path: http://10.10.10.150:80/index.php/2-uncategorised/2-curling-you-know-its-true
|     Line number: 165
|     Comment:
|         <!-- Begin Right Sidebar -->
|     
|     Path: http://10.10.10.150:80/index.php/2-uncategorised/2-curling-you-know-its-true
|     Line number: 29
|     Comment:
|         <!--[if lt IE 9]><script src="/media/system/js/polyfill.event.js?4c6b364068a1c45e7cd3bb9b6a49b052"></script><![endif]-->
|     
|     Path: http://10.10.10.150:80/index.php/2-uncategorised/2-curling-you-know-its-true
|     Line number: 222
|     Comment:
|         <!-- Footer -->
|     
|     Path: http://10.10.10.150:80/index.php/2-uncategorised/2-curling-you-know-its-true
|     Line number: 27
|     Comment:
|         <!--[if lt IE 9]><script src="/media/jui/js/html5.js?4c6b364068a1c45e7cd3bb9b6a49b052"></script><![endif]-->
|     
|     Path: http://10.10.10.150:80/index.php?format=feed&amp;type=atom
|     Line number: 2
|     Comment:
|         <!-- generator="Joomla! - Open Source Content Management" -->
|     
|     Path: http://10.10.10.150:80/index.php/2-uncategorised/2-curling-you-know-its-true
|     Line number: 162
|     Comment:
|         <!-- End Content -->
|     
|     Path: http://10.10.10.150:80/media/jui/js/bootstrap.min.js?4c6b364068a1c45e7cd3bb9b6a49b052
|     Line number: 1
|     Comment:
|         /*!
|          * Bootstrap.js by @fat & @mdo
|          * Copyright 2012 Twitter, Inc.
|          * http://www.apache.org/licenses/LICENSE-2.0.txt
|          *
|          * Custom version for Joomla!
|          */
|     
|     Path: http://10.10.10.150:80/index.php/2-uncategorised/2-curling-you-know-its-true
|     Line number: 39
|     Comment:
|         <!-- Body -->
|     
|     Path: http://10.10.10.150:80/index.php/component/users/?view=reset&amp;Itemid=101
|     Line number: 29
|     Comment:
|         <!--[if lt IE 9]><script src="/media/system/js/html5fallback.js?4c6b364068a1c45e7cd3bb9b6a49b052"></script><![endif]-->
|     
|     Path: http://10.10.10.150:80/templates/protostar/js/template.js?4c6b364068a1c45e7cd3bb9b6a49b052
|     Line number: 1
|     Comment:
|         /**
|          * @package     Joomla.Site
|          * @subpackage  Templates.protostar
|          * @copyright   Copyright (C) 2005 - 2018 Open Source Matters, Inc. All rights reserved.
|          * @license     GNU General Public License version 2 or later; see LICENSE.txt
|          * @since       3.2
|          */
|     
|     Path: http://10.10.10.150:80/media/jui/js/jquery-migrate.min.js?4c6b364068a1c45e7cd3bb9b6a49b052
|     Line number: 1
|     Comment:
|         /*! jQuery Migrate v1.4.1 | (c) jQuery Foundation and other contributors | jquery.org/license */
|     
|     Path: http://10.10.10.150:80/media/jui/js/html5.js?4c6b364068a1c45e7cd3bb9b6a49b052
|     Line number: 1
|     Comment:
|         /**
|         * @preserve HTML5 Shiv 3.7.3 | @afarkas @jdalton @jon_neal @rem | MIT/GPL2 Licensed
|         */
|     
|     Path: http://10.10.10.150:80/index.php/2-uncategorised/2-curling-you-know-its-true
|     Line number: 237
|     Comment:
|_        <!-- secret.txt -->
|_http-date: Fri, 26 Apr 2019 17:36:19 GMT; +6m13s from local time.
|_http-fetch: Please enter the complete path of the directory to save data in.
|_http-generator: Joomla! - Open Source Content Management
| http-grep:
|   (1) http://10.10.10.150:80/:
|     (1) ip:
|_      + 10.10.10.150
| http-headers:
|   Date: Fri, 26 Apr 2019 17:36:19 GMT
|   Server: Apache/2.4.29 (Ubuntu)
|   Set-Cookie: c0548020854924e0aecd05ed9f5b672b=omd5n9eo0uret9u3sj9ho7p07o; path=/; HttpOnly
|   Expires: Wed, 17 Aug 2005 00:00:00 GMT
|   Last-Modified: Fri, 26 Apr 2019 17:36:19 GMT
|   Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
|   Pragma: no-cache
|   Connection: close
|   Content-Type: text/html; charset=utf-8
|   
|_  (Request type: HEAD)
| http-internal-ip-disclosure:
|_  Internal IP Leaked: 250
|_http-mobileversion-checker: No mobile version detected.
|_http-referer-checker: Couldn't find any cross-domain scripts.
| http-security-headers:
|   Cache_Control:
|     Header: Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
|   Pragma:
|     Header: Pragma: no-cache
|   Expires:
|_    Header: Expires: Wed, 17 Aug 2005 00:00:00 GMT
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Home
| http-traceroute:
|   last-modified
|     Hop #1: Fri, 26 Apr 2019 17:36:15 GMT
|     Hop #2: Fri, 26 Apr 2019 17:36:16 GMT
|_    Hop #3: Fri, 26 Apr 2019 17:36:17 GMT
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
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 6m12s, deviation: 0s, median: 6m12s
|_fcrdns: FAIL (No PTR record)
|_ipidseq: All zeros
|_path-mtu: PMTU == 1500
| qscan:
| PORT  FAMILY  MEAN (us)  STDDEV    LOSS (%)
| 1     0       397982.50  63132.29  0.0%
| 22    1       327267.89  49047.70  10.0%
|_80    0       349985.20  78775.50  0.0%

Post-scan script results:
| reverse-index:
|   22/tcp: 10.10.10.150
|_  80/tcp: 10.10.10.150
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 198.14 seconds

```

## UDP
