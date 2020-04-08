# Discovery

## Tools

### Subdomains 

```
wfuzz -u https://(TARGET DOMAIN NAME) -w /infosec/wordlists/SecLists/Discovery/DNS/subdomains-list-5000.txt -H "Host: FUZZ.(TARGET DOMAIN NAME)"
```

### Files and Folders

- Gobuster: https://github.com/OJ/gobuster
- DirBuster: https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
- EroDir: A fast web directory/file enumeration tool written in Rust: https://github.com/PinkP4nther/EroDir
- DeepSearch: https://github.com/m4ll0k/DeepSearch
- Filebuster - An extremely fast and flexible web fuzzer: [https://github.com/henshin/filebuster](https://github.com/henshin/filebuster)
```
#!/bin/bash
set -eu

URL=$1

echo "super go bustering for super brute: $URL"

gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/tomcat.txt
gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/nginx.txt
gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/apache.txt
gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt
gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/ApacheTomcat.fuzz.txt
gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/sharepoint.txt
gobuster -u $URL -l -s 200,204,301,302,307,403 -w /root/tools/SecLists/Discovery/Web_Content/iis.txt
gobuster -u $URL -l -s 200,204,301,302,307,403 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster -u $URL -l -s 200,204,301,302,307,403 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -x txt
gobuster -u $URL -l -s 200,204,301,302,307,403 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -x php 
gobuster -u $URL -l -s 200,204,301,302,307,403 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -x doc 
gobuster -u $URL -l -s 200,204,301,302,307,403 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -x docx

```

### Parameters

- WFuzz - Identity parameter names
```
 wfuzz -c -z file,burp-parameter-names.txt --hh=19 http://10.10.10.69/sync?FUZZ=writeup
```

- Word-lists
  - [https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt)

### Interesting files

- pyHAWK: Searches the directory of choice for interesting files. Such as database files and files with passwords stored on them: https://github.com/MetaChar/pyHAWK

### Technology

- WhatWeb - recognises web technologies (& versions): [https://github.com/urbanadventurer/WhatWeb](https://github.com/urbanadventurer/WhatWeb)

### Site Mapping

- [skipfish](https://code.google.com/archive/p/skipfish/)

## References

- Hidden directories and files as a source of sensitive information about web application: https://medium.com/@_bl4de/hidden-directories-and-files-as-a-source-of-sensitive-information-about-web-application-84e5c534e5ad
