## Volatility 

- Cheatsheet: <https://digital-forensics.sans.org/media/volatility-memory-forensics-cheat-sheet.pdf>
```
volatility -f example.dmp imageinfo
volatility -f example.dmp --profile Win2012R2x64 lsadump
volatility -f example.dmp --profile Win2012R2x64 hivelist 
volatility -f example.dmp --profile Win2012R2x64 hashdump -y 0xffffc00000028000 -s 0xffffc00000619000 
  -y is virtual address of SYSTEM hive
  -s is virtual address of SYSTEM hive
```
