## Nikto

## DirBuster / GoBuster

## WebDav

## CMS

```
 wpscan --url https://brainfuck.htb --disable-tls-checks
_______________________________________________________________
        __          _______   _____
        \ \        / /  __ \ / ____|
         \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
           \  /\  /  | |     ____) | (__| (_| | | | |
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|

        WordPress Security Scanner by the WPScan Team
                       Version 3.4.3
          Sponsored by Sucuri - https://sucuri.net
      @_WPScan_, @ethicalhack3r, @erwan_lr, @_FireFart_
_______________________________________________________________

[+] URL: https://brainfuck.htb/
[+] Started: Tue Apr 23 07:32:44 2019

Interesting Finding(s):

[+] https://brainfuck.htb/
 | Interesting Entry: Server: nginx/1.10.0 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] https://brainfuck.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] https://brainfuck.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 4.7.3 identified (Insecure, released on 2017-03-06).
 | Detected By: Rss Generator (Passive Detection)
 |  - https://brainfuck.htb/?feed=rss2, <generator>https://wordpress.org/?v=4.7.3</generator>
 |  - https://brainfuck.htb/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.7.3</generator>
 |
 | [!] 34 vulnerabilities identified:
 |
 | [!] Title: WordPress 2.3-4.8.3 - Host Header Injection in Password Reset
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8807
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8295
 |      - https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html
 |      - http://blog.dewhurstsecurity.com/2017/05/04/exploitbox-wordpress-security-advisories.html
 |      - https://core.trac.wordpress.org/ticket/25239
 |
 | [!] Title: WordPress 2.7.0-4.7.4 - Insufficient Redirect Validation
 |     Fixed in: 4.7.5
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8815
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9066
 |      - https://github.com/WordPress/WordPress/commit/76d77e927bb4d0f87c7262a50e28d84e01fd2b11
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |
 | [!] Title: WordPress 2.5.0-4.7.4 - Post Meta Data Values Improper Handling in XML-RPC
 |     Fixed in: 4.7.5
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8816
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9062
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/3d95e3ae816f4d7c638f40d3e936a4be19724381
 |
 | [!] Title: WordPress 3.4.0-4.7.4 - XML-RPC Post Meta Data Lack of Capability Checks 
 |     Fixed in: 4.7.5
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8817
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9065
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/e88a48a066ab2200ce3091b131d43e2fab2460a4
 |
 | [!] Title: WordPress 2.5.0-4.7.4 - Filesystem Credentials Dialog CSRF
 |     Fixed in: 4.7.5
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8818
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9064
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/38347d7c580be4cdd8476e4bbc653d5c79ed9b67
 |      - https://sumofpwn.nl/advisory/2016/cross_site_request_forgery_in_wordpress_connection_information.html
 |
 | [!] Title: WordPress 3.3-4.7.4 - Large File Upload Error XSS
 |     Fixed in: 4.7.5
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8819
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9061
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/8c7ea71edbbffca5d9766b7bea7c7f3722ffafa6
 |      - https://hackerone.com/reports/203515
 |      - https://hackerone.com/reports/203515
 |
 | [!] Title: WordPress 3.4.0-4.7.4 - Customizer XSS & CSRF
 |     Fixed in: 4.7.5
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8820
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9063
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/3d10fef22d788f29aed745b0f5ff6f6baea69af3
 |
 | [!] Title: WordPress 2.3.0-4.8.1 - $wpdb->prepare() potential SQL Injection
 |     Fixed in: 4.7.6
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8905
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/70b21279098fc973eae803693c0705a548128e48
 |      - https://github.com/WordPress/WordPress/commit/fc930d3daed1c3acef010d04acc2c5de93cd18ec
 |
 | [!] Title: WordPress 2.3.0-4.7.4 - Authenticated SQL injection
 |     Fixed in: 4.7.5
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8906
 |      - https://medium.com/websec/wordpress-sqli-bbb2afcc8e94
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/70b21279098fc973eae803693c0705a548128e48
 |      - https://wpvulndb.com/vulnerabilities/8905
 |
 | [!] Title: WordPress 2.9.2-4.8.1 - Open Redirect
 |     Fixed in: 4.7.6
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8910
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14725
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41398
 |
 | [!] Title: WordPress 3.0-4.8.1 - Path Traversal in Unzipping
 |     Fixed in: 4.7.6
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8911
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14719
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41457
 |
 | [!] Title: WordPress 4.4-4.8.1 - Path Traversal in Customizer 
 |     Fixed in: 4.7.6
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8912
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14722
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41397
 |
 | [!] Title: WordPress 4.4-4.8.1 - Cross-Site Scripting (XSS) in oEmbed
 |     Fixed in: 4.7.6
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8913
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14724
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41448
 |
 | [!] Title: WordPress 4.2.3-4.8.1 - Authenticated Cross-Site Scripting (XSS) in Visual Editor
 |     Fixed in: 4.7.6
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8914
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14726
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41395
 |      - https://blog.sucuri.net/2017/09/stored-cross-site-scripting-vulnerability-in-wordpress-4-8-1.html
 |
 | [!] Title: WordPress <= 4.8.2 - $wpdb->prepare() Weakness
 |     Fixed in: 4.7.7
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8941
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16510
 |      - https://wordpress.org/news/2017/10/wordpress-4-8-3-security-release/
 |      - https://github.com/WordPress/WordPress/commit/a2693fd8602e3263b5925b9d799ddd577202167d
 |      - https://twitter.com/ircmaxell/status/923662170092638208
 |      - https://blog.ircmaxell.com/2017/10/disclosure-wordpress-wpdb-sql-injection-technical.html
 |
 | [!] Title: WordPress 2.8.6-4.9 - Authenticated JavaScript File Upload
 |     Fixed in: 4.7.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8966
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17092
 |      - https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/67d03a98c2cae5f41843c897f206adde299b0509
 |
 | [!] Title: WordPress 1.5.0-4.9 - RSS and Atom Feed Escaping
 |     Fixed in: 4.7.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8967
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17094
 |      - https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/f1de7e42df29395c3314bf85bff3d1f4f90541de
 |
 | [!] Title: WordPress 4.3.0-4.9 - HTML Language Attribute Escaping
 |     Fixed in: 4.7.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8968
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17093
 |      - https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/3713ac5ebc90fb2011e98dfd691420f43da6c09a
 |
 | [!] Title: WordPress 3.7-4.9 - 'newbloguser' Key Weak Hashing
 |     Fixed in: 4.7.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8969
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17091
 |      - https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/eaf1cfdc1fe0bdffabd8d879c591b864d833326c
 |
 | [!] Title: WordPress 3.7-4.9.1 - MediaElement Cross-Site Scripting (XSS)
 |     Fixed in: 4.7.9
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9006
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5776
 |      - https://github.com/WordPress/WordPress/commit/3fe9cb61ee71fcfadb5e002399296fcc1198d850
 |      - https://wordpress.org/news/2018/01/wordpress-4-9-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/ticket/42720
 |
 | [!] Title: WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9021
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6389
 |      - https://baraktawily.blogspot.fr/2018/02/how-to-dos-29-of-world-wide-websites.html
 |      - https://github.com/quitten/doser.py
 |      - https://thehackernews.com/2018/02/wordpress-dos-exploit.html
 |
 | [!] Title: WordPress 3.7-4.9.4 - Remove localhost Default
 |     Fixed in: 4.7.10
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9053
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10101
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/804363859602d4050d9a38a21f5a65d9aec18216
 |
 | [!] Title: WordPress 3.7-4.9.4 - Use Safe Redirect for Login
 |     Fixed in: 4.7.10
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9054
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10100
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/14bc2c0a6fde0da04b47130707e01df850eedc7e
 |
 | [!] Title: WordPress 3.7-4.9.4 - Escape Version in Generator Tag
 |     Fixed in: 4.7.10
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9055
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10102
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/31a4369366d6b8ce30045d4c838de2412c77850d
 |
 | [!] Title: WordPress <= 4.9.6 - Authenticated Arbitrary File Deletion
 |     Fixed in: 4.7.11
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9100
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12895
 |      - https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution/
 |      - http://blog.vulnspy.com/2018/06/27/Wordpress-4-9-6-Arbitrary-File-Delection-Vulnerbility-Exploit/
 |      - https://github.com/WordPress/WordPress/commit/c9dce0606b0d7e6f494d4abe7b193ac046a322cd
 |      - https://wordpress.org/news/2018/07/wordpress-4-9-7-security-and-maintenance-release/
 |      - https://www.wordfence.com/blog/2018/07/details-of-an-additional-file-deletion-vulnerability-patched-in-wordpress-4-9-7/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated File Delete
 |     Fixed in: 4.7.12
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9169
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20147
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Post Type Bypass
 |     Fixed in: 4.7.12
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9170
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20152
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://blog.ripstech.com/2018/wordpress-post-type-privilege-escalation/
 |
 | [!] Title: WordPress <= 5.0 - PHP Object Injection via Meta Data
 |     Fixed in: 4.7.12
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9171
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20148
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Cross-Site Scripting (XSS)
 |     Fixed in: 4.7.12
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9172
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20153
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Cross-Site Scripting (XSS) that could affect plugins
 |     Fixed in: 4.7.12
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9173
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20150
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/fb3c6ea0618fcb9a51d4f2c1940e9efcd4a2d460
 |
 | [!] Title: WordPress <= 5.0 - User Activation Screen Search Engine Indexing
 |     Fixed in: 4.7.12
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9174
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20151
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - File Upload to XSS on Apache Web Servers
 |     Fixed in: 4.7.12
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9175
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20149
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/246a70bdbfac3bd45ff71c7941deef1bb206b19a
 |
 | [!] Title: WordPress 3.7-5.0 (except 4.9.9) - Authenticated Code Execution
 |     Fixed in: 5.0.1
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9222
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8942
 |      - https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/
 |
 | [!] Title: WordPress 3.9-5.1 - Comment Cross-Site Scripting (XSS)
 |     Fixed in: 4.7.13
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9230
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9787
 |      - https://github.com/WordPress/WordPress/commit/0292de60ec78c5a44956765189403654fe4d080b
 |      - https://wordpress.org/news/2019/03/wordpress-5-1-1-security-and-maintenance-release/
 |      - https://blog.ripstech.com/2019/wordpress-csrf-to-rce/

[+] WordPress theme in use: proficient
 | Location: https://brainfuck.htb/wp-content/themes/proficient/
 | Last Updated: 2018-02-16T00:00:00.000Z
 | Readme: https://brainfuck.htb/wp-content/themes/proficient/readme.txt
 | [!] The version is out of date, the latest version is 1.1.24
 | Style URL: https://brainfuck.htb/wp-content/themes/proficient/style.css?ver=4.7.3
 | Style Name: Proficient
 | Description: Proficient is a Multipurpose WordPress theme with lots of powerful features, instantly giving a prof...
 | Author: Specia
 | Author URI: https://speciatheme.com/
 |
 | Detected By: Css Style (Passive Detection)
 |
 | Version: 1.0.6 (80% confidence)
 | Detected By: Style (Passive Detection)
 |  - https://brainfuck.htb/wp-content/themes/proficient/style.css?ver=4.7.3, Match: 'Version: 1.0.6'

[+] Enumerating All Plugins
[+] Checking Plugin Versions

[i] Plugin(s) Identified:

[+] wp-support-plus-responsive-ticket-system
 | Location: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/
 | Last Updated: 2019-04-16T06:36:00.000Z
 | [!] The version is out of date, the latest version is 9.1.2
 |
 | Detected By: Urls In Homepage (Passive Detection)
 |
 | [!] 4 vulnerabilities identified:
 |
 | [!] Title: WP Support Plus Responsive Ticket System <= 7.1.3 – Authenticated SQL Injection
 |     Fixed in: 8.0.0
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8699
 |      - https://www.exploit-db.com/exploits/40939/
 |      - http://lenonleite.com.br/en/blog/2016/12/13/wp-support-plus-responsive-ticket-system-wordpress-plugin-sql-injection/
 |      - https://plugins.trac.wordpress.org/changeset/1556644/wp-support-plus-responsive-ticket-system
 |
 | [!] Title: WP Support Plus Responsive Ticket System <= 8.0.7 - Remote Code Execution (RCE)
 |     Fixed in: 8.0.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8949
 |      - https://plugins.trac.wordpress.org/changeset/1763596/wp-support-plus-responsive-ticket-system
 |
 | [!] Title: WP Support Plus Responsive Ticket System <= 9.0.2 - Multiple Authenticated SQL Injection
 |     Fixed in: 9.0.3
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9041
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000131
 |      - https://github.com/00theway/exp/blob/master/wordpress/wpsupportplus.md
 |      - https://plugins.trac.wordpress.org/changeset/1814103/wp-support-plus-responsive-ticket-system
 |
 | [!] Title: WP Support Plus Responsive Ticket System <= 9.1.1 - Stored XSS
 |     Fixed in: 9.1.2
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9235
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7299
 |      - https://cert.kalasag.com.ph/news/research/cve-2019-7299-stored-xss-in-wp-support-plus-responsive-ticket-system/
 |      - https://plugins.trac.wordpress.org/changeset/2024484/wp-support-plus-responsive-ticket-system
 |
 | Version: 7.1.3 (100% confidence)
 | Detected By: Readme - Stable Tag (Aggressive Detection)
 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt

[+] Enumerating Config Backups
 Checking Config Backups - Time: 00:00:03 <===========================================================================================================> (21 / 21) 100.00% Time: 00:00:03

[i] No Config Backups Found.

[+] Finished: Tue Apr 23 07:33:00 2019
[+] Requests Done: 53
[+] Cached Requests: 4
[+] Data Sent: 10.006 KB
[+] Data Received: 168.808 KB
[+] Memory used: 86.762 MB
[+] Elapsed time: 00:00:16
```



