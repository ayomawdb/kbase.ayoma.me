# Cheatsheet

## Enable xp_cmdshell

```
exec sp_configure ‘show advanced options’, 1
reconfigure
exec sp_configure ‘xp_cmdshell’, 1
reconfigure
```
