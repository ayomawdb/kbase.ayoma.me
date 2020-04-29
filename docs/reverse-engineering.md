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