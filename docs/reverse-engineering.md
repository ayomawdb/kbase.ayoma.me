## Tools

- Diaphora - is a program diffing plugin for IDA / Ghidra: <https://github.com/joxeankoret/diaphora>
- radare2
- Frida - Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers: <https://www.frida.re/>
- angr - Python framework for analyzing binaries. It combines both static and dynamic symbolic ("concolic") analysis, making it applicable to a variety of tasks: <https://angr.io/>
- GEF - GDB Enhanced Features for exploit devs & reversers: <https://github.com/hugsy/gef>
- YY-CHR - Supports editing NES, SNES, Genesis, PCE, GG, WS/C, GB/C, MSX 1+2, NGP/C, SMS, and GBA graphics: <https://www.romhacking.net/utilities/119/>
- ProcDump - ProcDump provides a convenient way for Linux developers to create core dumps of their application based on performance triggers: <https://github.com/Microsoft/ProcDump-for-Linux>
- mleak - Memory leak tracer for C programs: <https://github.com/hyc/mleak>
- Demangle function names (C/C++): <http://demangler.com>

## Collections

- Vagrant box with binary analysis tools: <https://github.com/Hamz-a/binanalysisbox>

## Language/OS Specific 

### Linux

**Setup**

- Disable ASLR: `sudo sysctl -w kernel.randomize_va_space=0`
- Allow ptrace processes: `sudo sysctl -w kernel.yama.ptrace_scope=0`
- Installing 32bit Libraries
    ```bash
    dpkg --add-architecture i386
    apt-get install libc6:i386
    ```
**GDB**

- PEDA: <http://ropshell.com/peda/Linux_Interactive_Exploit_Development_with_GDB_and_PEDA_Slides.pdf>

- Run GBD with env variables: `env - gdb /bin/lcars`
- Display Information
    ```
    info registers
    info all-registers
    ```
- Display memory map: `vmmap`
- Display Registers / Memory: `display /x $eax` `x/50c $eax` `x/s $eax`
- Disassemble-flavor: `set disassembly-flavor intel`
- Disassemble: `disassemble $eip`
- Print Type Information: `ptype Student`
- Check security information: `checksec`

**References**

- ELF Binary Mangling Part 1 — Concepts: <https://medium.com/@dmxinajeansuit/elf-binary-mangling-part-1-concepts-e00cb1352301>
- Elf Binary Mangling Pt. 2: Golfin’: <https://medium.com/@dmxinajeansuit/elf-binary-mangling-pt-2-golfin-7e5c82bb482c>
- Elf Binary Mangling Part 3 — Weaponization: <https://medium.com/@dmxinajeansuit/elf-binary-mangling-part-3-weaponization-6e11971108b3>
- <http://romainthomas.fr/slides/18-06-Recon18-Formats-Instrumentation.pdf>
- Dissecting and exploiting ELF files: <https://0x00sec.org/t/dissecting-and-exploiting-elf-files/7267>

### Windows

**Tools**

- Collections
  - A list of static analysis tools for Portable Executable (PE) files: <https://www.peerlyst.com/posts/a-list-of-static-analysis-tools-for-portable-executable-pe-files-susan-parker?utm_source=twitter&utm_medium=social&utm_content=peerlyst_post&utm_campaign=peerlyst_shared_post>
- Generate call graphs from VBA code -  <https://github.com/MalwareCantFly/Vba2Graph>
- libpeconv - A library to load, manipulate, dump PE files <https://github.com/hasherezade/libpeconv>
- filealyzer - Helps you explore alternate data streams, #PE/#ELF data and anomalies, file signatures, EXIF data, MZ header, #OpenSBI, #PEiD, #VirusTotal, Android and iOS app (file) info, all in one neat UI: <https://www.safer-networking.org/products/filealyzer/>
- WinDbg - Toy scripts for playing with WinDbg JS API: <https://github.com/hugsy/windbg_js_scripts>
- HXD - Hex Editor: <https://mh-nexus.de/en/hxd/>

**Defense**

- Control Flow Guard - Protects the execution flow from redirection - for example, from exploits that overwrite an address in the stack <https://86hh.github.io/cfg.html>

**References**

- Rich Header - <http://bytepointer.com/articles/the_microsoft_rich_header.htm>
- Learning binary file formats: 
  - <https://board.flatassembler.net/topic.php?t=20690>
  - <https://twitter.com/grysztar/status/1088901193747845120>


### .NET

- File Format
  - `.text` - Import Table, Import Address Table and .NET Section
  - `.reloc` - To relocate the address which the EntryPoint instruction jumps to (it's the only address contained the IAT). The IT counts just one imported module (mscoree.dll) and one imported function (\_CorExeMain for executables and \_CorDllMain for dynamic load libraries).
  - `.rsrc` - Main icon for an executable, since all others resources are in the .NET Section.
  - <https://www.ntcore.com/files/dotnetformat.htm>
  - <https://www.red-gate.com/simple-talk/blogs/anatomy-of-a-net-assembly-pe-headers/>
- Dynamically load memory-only modules: [Assembly.Load(byte[])](https://msdn.microsoft.com/en-us/library/system.reflection.assembly.load)
  - <https://www.endgame.com/blog/technical-blog/hunting-memory-net-attacks>
- .NET framework included in OS version: <https://blogs.msdn.microsoft.com/astebner/2007/03/14/mailbag-what-version-of-the-net-framework-is-included-in-what-version-of-the-os/>

**Tools**

- CFF Explorer: <https://ntcore.com/?page_id=388>
- PE inspection library allowing .NET programmers to read, modify and write executable files: <https://github.com/Washi1337/AsmResolver>
- Parser for Windows Portable Executable headers: <https://github.com/secana/PeNet>

**References**

- Reverse Engineering .NET Applications For Beginners: <https://www.youtube.com/watch?v=KOVXWRrd_qg>

## Practice

- <https://www.malwaretech.com/beginner-malware-reversing-challenges>

## Defense

- Disassembly desynchronization: <https://github.com/yellowbyte/analysis-of-anti-analysis/blob/master/research/the_return_of_disassembly_desynchronization/the_return_of_disassembly_desynchronization.md>

## References

- 101 - <https://www.youtube.com/watch?v=Min6DWTHDBw&feature=em-uploademail>
- Reverse Engineering for Beginners: <https://www.begin.re/>
- Learning Radare2 by Reversing a UMPC Bios: <https://stragedevices.blogspot.com/2019/02/finding-verified-intel-atom-msrs-in.html>
- Survival guide for Radare2 with practice: <https://github.com/ZigzagSecurity/survival-guide-radare2>
- <http://www.capstone-engine.org/showcase.html>
- Reverse engineering simple binaries created in Fortran, C, C++, Pascal and Ada: <https://www.mkdynamics.net/current_projects/computer_security/Disassembling_binaries/disassembling_binaries.html>
- Port-oriented Programming: <https://twitter.com/bxl1989/status/1085101696735268865>
- OALabs - WinDbg Basics for Malware Analysis: <https://www.youtube.com/watch?v=QuFJpH3My7A&list=PLGf_j68jNtWG_6ZwFN4kx7jfKTQXoG_BN>
- The 101 of ELF files on Linux: Understanding and Analysis: <https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/>
- Ground Zero: Reverse Engineering: <https://scriptdotsh.com/index.php/category/reverse-engineering/>

**ARM**

- SUE 2017 - Reverse Engineering Embedded ARM Devices - by pancake: https://www.youtube.com/watch?v=oXSx0Qo2Upk&feature=youtu.be
- ARM ASSEMBLY BASICS CHEATSHEET: https://azeria-labs.com/assembly-basics-cheatsheet/

**GO**

- Set of IDA Pro scripts for parsing GoLang types information stored in compiled binary: https://github.com/sibears/IDAGolangHelper

**Java**

- Toold, JADX, JD-GUI, Procyon, CFR, Fernflower etc., Bytecodeviewer, dex2jar, APK tool 

**Mobile Apps**

- Inro: <https://medium.com/@xplodwild/turning-the-frustration-of-a-mobile-game-into-a-reverse-engineering-training-a9887043efdf>
- They updated, we dumped memory: <https://blog.usejournal.com/reverse-engineering-of-a-mobile-game-part-2-they-updated-we-dumped-memory-27046efdfb85>
- Now, it’s obfuscated: <https://medium.com/@xplodwild/reverse-engineering-of-a-mobile-game-part-3-now-its-obfuscated-9c31e29c386b>