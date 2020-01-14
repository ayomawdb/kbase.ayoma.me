
https://social.msdn.microsoft.com/Forums/sqlserver/en-US/31d57870-1faa-4e14-8527-ce77b1ff40e4/local-service-local-system-or-network-service?forum=sqlsecurity

### Local System

Local System is a very high-privileged built-in account. It has extensive privileges on the local system and acts as the computer on the network. The actual name of the account is "NT AUTHORITY\SYSTEM".

### Local Service
The Local Service account is a built-in account that has the same level of access to resources and objects as members of the Users group. This limited access helps safeguard the system if individual services or processes are compromised. Services that run as the Local Service account access network resources as a null session without credentials. Be aware that the Local Service account is not supported for the SQL Server or SQL Server Agent services. The actual name of the account is "NT AUTHORITY\LOCAL SERVICE".

### Network Service

The Network Service account is a built-in account that has more access to resources and objects than members of the Users group. Services that run as the Network Service account access network resources by using the credentials of the computer account. The actual name of the account is "NT AUTHORITY\NETWORK SERVICE"
