# PHP

## References
- https://eev.ee/blog/2012/04/09/php-a-fractal-of-bad-design/
- https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/
- http://pentestmonkey.net/tools/web-shells/php-reverse-shell

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
