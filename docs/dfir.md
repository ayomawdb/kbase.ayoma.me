# DFIR

## Linux 

### Disk 

#### Deleted files

Linux
```
lost+found
```
```
strings /dev/sdb
```
```
sudo dcfldd if=/dev/sdb of=/home/pi/usb.dd
testdisk /home/pi/usb.dd
```

#### Temp files 

- myfile.txt~
- .myfile.txt.swp
- .myfile.txt.un~
- .backup

## Windows 

### Disk

- Mount: <https://accessdata.com/product-download/ftk-imager-version-4.2.0>
- Autopsy: <http://www.sleuthkit.org/autopsy/>
  - Show attribute ID of NTFS file systems (fls)
- The Sleuth Kit: <http://www.sleuthkit.org/sleuthkit/>
- NTFS Log Tracker: <https://sites.google.com/site/forensicnote/ntfs-log-tracker>
- SIFT
  - Beginning of partition: mmls <image>
  - Assemble image in raw: ewfmount <image> /mnt/disk1
  - obtain shadow file information: vshadowinfo -o <val> /mnt/disk1/ewf1
    - val = partition start value from mmls * 512
  - Mount shadow: vshadowmount -o <val>  /mnt/disk1/ewf1 /mnt/vss
    - mount -o ro,loop /mnt/vss/vss1 /mnt/disk2
- Volume serial number
  - Position 0x48 of the BPB (Bios Parameter Block), which is part of the boot sector.
  - $ boot - mount with FTK Imager
  - Or use "vol" command
  - <https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc781134(v=ws.10)>
  - <https://www.digital-detective.net/documents/Volume%20Serial%20Numbers.pdf>

### Registry

```
C: \ Windows \ system32 \ config
```

- <http://www.regxplor.com/>
- <https://ericzimmerman.github.io/#!index.>
- RegRipper - Etracting/parsing information (keys, values, data) from the Registry and presenting it for analysis: <https://github.com/keydet89/RegRipper2.8>
- RECmd - Command line access to the Registry: <https://github.com/EricZimmerman/RECmd>
- Timezone: `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation`
- Computer Name: `HKLM\SYSTEM\CurrentControlSet\Control\ComputerName`
- Last Shutdown: `HKLM\SYSTEM\CurrentControlSet\Control\Windows` -> `ShutdownTime`
- Build Number:  `HKLM\SOFTWARE\Microsoft\Windows\NT\CurrentVersion\CurrentBuildNumber`
- Important Registry Locations Collection: <https://www.dfir.training/resources/downloads/windows-registry>

### Important Files

**`$MFT` Master File Table**

- Kind of index of all files on the hard drive
- <https://jmharkness.wordpress.com/2011/01/27/mft-file-reference-number/>
- All the entries of the MFT have a reference number, composed of the number of the MFT entry (6 bytes) and the sequence number (2 bytes) in hexadecimal.
  - Ref: 0x002E00000000F1AB -> MFT entry: 00000000F1AB, Sequence number: 0x002E
- Can be dumped with: <http://malware-hunters.net/all-downloads/>

**`MRU` Most Recently Used**

- NTUSER.dat
- Can be read with `RegRipper` with the plugin `runmru`.
  - Pulling the UserAssist, which stores the latest applications, shortcuts and documents opened by the user
    - `rip.exe -p userassist -r ../NTUSER.DAT`

**`USN` Journal (Update Sequence Number Journal)**

- Keeps a log of the changes that are made in an NTFS volume
- <http://forensicinsight.org/wp-content/uploads/2013/07/F-INSIGHT-Advanced-UsnJrnl-Forensics-English.pdf>
- Extract the log with FTK Imager
- parse this journal with the NTFS Log Tracker: <https://sites.google.com/site/forensicnote/ntfs-log-tracker>

```
C: \ $ Extend \ $ UsrJrnl,
```

**Logs:**

```
C: \ Windows \ system32 \ winevt \ logs
```

**User logins:**

Each time a session is started the user profile is loaded. This action leaves a record in the `Microsoft-Windows-User Profile Service log/Operational.evtx`

**Prefetch:**

**File extensions of interest:**

- <http://www.hexacorn.com/blog/2019/02/11/file-extensions-of-interest/>

## Common 

### Memory 

- Volatility 
  - Cheatsheet: <https://digital-forensics.sans.org/media/volatility-memory-forensics-cheat-sheet.pdf>
    ```
    volatility -f example.dmp imageinfo
    volatility -f example.dmp --profile Win2012R2x64 lsadump
    volatility -f example.dmp --profile Win2012R2x64 hivelist 
    volatility -f example.dmp --profile Win2012R2x64 hashdump -y 0xffffc00000028000 -s 0xffffc00000619000 
    -y is virtual address of SYSTEM hive
    -s is virtual address of SYSTEM hive
    ```

## CTFs

- Challenges & CTFs: <https://aboutdfir.com/challenges-ctfs/>

## Writeups

- DEFCON 2018 DFIR CTF - Forensic Challenge (Level 1): <https://www.securityartwork.es/2019/01/04/defcon-2018-dfir-ctf-reto-forense-intro-nivel-1/>
- DEFCON 2018 DFIR CTF - Forensic Challenge (Level 2): <https://www.securityartwork.es/2019/01/07/defcon-2018-dfir-ctf-reto-forense-nivel-2/>
- DEFCON 2018 DFIR CTF - Forensic Challenge (Level 3): <https://www.securityartwork.es/2019/01/08/defcon-2018-dfir-ctf-reto-forense-nivel-3-conclusiones/>
- DEFCON DFIR CTF 2018 — Lessons Learned: <https://medium.com/@monliclican/defcon-dfir-ctf-2018-lessons-learned-890ef781b96c>

## References

### Books

- File System Forensic Analysis: <https://www.amazon.com/System-Forensic-Analysis-Brian-Carrier-ebook/dp/B000OZ0N9O>

### New References

- So you want to be a Digital Forensics professional: <https://www.peerlyst.com/posts/so-you-want-to-be-a-digital-forensics-professional-calvin-liu?utm_source=twitter&utm_medium=social&utm_content=peerlyst_post&utm_campaign=peerlyst_shared_post>

### Cheatsheets

- Linux Command Line Forensics and Intrusion Detection Cheat Sheet: <https://www.sandflysecurity.com/blog/compromised-linux-cheat-sheet/>
- "Hunt Evil: Lateral Movement": <https://www.sans.org/security-resources/posters/dfir/hunt-evil-165?utm_medium=Social&utm_source=Twitter&utm_content=May+HuntEvil+Registration+Twitter_RSR&utm_campaign=DFIR+Poster>
- Windows Forensic Analysis : POSTER: <https://www.sans.org/security-resources/posters/windows-forensics-evidence-of/75/download?utm_medium=Social&utm_source=Twitter&utm_content=June+APAC+WindowsForensics_RSR&utm_campaign=DFIR+Poster>
- Advanced Smartphone Forensics : POSTER: <https://digital-forensics.sans.org/media/DFIR-Smartphone-Forensics-Poster.pdf>
