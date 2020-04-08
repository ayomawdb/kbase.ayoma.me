
## Configuration files
```
containers.ldif
ldap.cfg
ldap.conf
ldap.xml
ldap-config.xml
ldap-realm.xml
slapd.conf
```

## Tools
- Softerra LDAP Administrator
- Jxplorer
- active directory domain services management pack for system center
- LDAP Admin Tool
- LDAP Administrator tool


## Brute-forcing

```
nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=schema,dc=targetbox,dc=target"' (TARGET IP ADDRESS) -vv
```

## Dump
```
ldapdomaindump -u example\example 10.10.10.10
```
```
ldapsearch -LLL -x -H ldap://<domain> -b "" -s base "(objectclass=*)"
```
```
ldapsearch -LLL -x -H ldap://<domain> -b "" -s base "CN=example,DC=LOCAL"
```
```
ldapsearch -h EGOTISTICAL-BANK.LOCAL -p 389 -x -b "DC=EGOTISTICAL-BANK,DC=LOCAL"
```

http://jrwren.wrenfam.com/blog/2006/11/17/querying-active-directory-with-unix-ldap-tools/index.html