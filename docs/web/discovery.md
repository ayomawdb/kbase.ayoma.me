# Discovery

## Tools

### Files and Folders

- Gobuster: https://github.com/OJ/gobuster
- DirBuster: https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
- EroDir: A fast web directory/file enumeration tool written in Rust: https://github.com/PinkP4nther/EroDir
- DeepSearch: https://github.com/m4ll0k/DeepSearch
- Filebuster - An extremely fast and flexible web fuzzer: [https://github.com/henshin/filebuster](https://github.com/henshin/filebuster)
### Parameters

- WFuzz - Identity parameter names
```
​ wfuzz -c -z file,burp-parameter-names.txt --hh=19 http://10.10.10.69/sync?FUZZ=writeup
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
