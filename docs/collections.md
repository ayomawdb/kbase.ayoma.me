## Binaries 

- Nmap: - <https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/>

## Leaked Datasets

Disclaimer: These links are intended to be used by information security researchers who are interested in understanding the capabilities of frameworks/data-sets used in real-life. I am not responsible if you choose to use my work or this documentation to do something dumb and/or illegal.

### Shadowbroker

- <https://www.comae.com/reports/us-17-Suiche-TheShadowBrokers-Cyber-Fear-Game-Changers-wp.pdf>
- <https://swithak.github.io/SH20TAATSB18/Study/AnalysesANDProfiles/TSB-ZeroNet/>
- <https://lostar.com.tr/2017/04/nsa-hepimizi-izliyor.html>
- <https://www.revolvy.com/page/The-Shadow-Brokers>
- [EQGRP Lost in Translation](https://github.com/x0rz/EQGRP_Lost_in_Translation)
  - References:
    - [MUSTREAD]: [Buckeye: Espionage Outfit Used Equation Group Tools Prior to Shadow Brokers Leak](https://www.symantec.com/blogs/threat-intelligence/buckeye-windows-zero-day-exploit)
    - [Confirmed: Leaked Equation Group Hacking Tools Are Real](https://www.bankinfosecurity.com/equation-group-toolset-real-but-was-leaked-a-9344)
    - [https://www.symantec.com/blogs/threat-intelligence/buckeye-windows-zero-day-exploit](https://www.symantec.com/blogs/threat-intelligence/buckeye-windows-zero-day-exploit)
    - [https://github.com/misterch0c/shadowbroker](https://github.com/misterch0c/shadowbroker)
    - DanderSpritz
      - [https://github.com/francisck/DanderSpritz_docs](https://github.com/francisck/DanderSpritz_docs)
  - DanderSpritz
    - [Setup - https://danderspritz.com/](https://danderspritz.com/)
    - **DSky	Darkskyline**	PacketCapture tool
    - **DaPu	DarkPulsar**	Appears to be a legacy implant, similar to PeddleCheap but older
    - **Darkskyline	DarkSkyline**	Contains tools to parse and filter traffic captured by DarkSkyline
    - **DeMI	DecibelMinute**	Appears to interact with KillSuit to install, configure, and uninstall it
    - **Df	DoubleFeature**	Generates a log & report about the types of tools that could be deployed on the target. A lot of tools mention that doublefeature is the only way to confirm their existence
    - **DmGZ	DoormanGauze**	DoormanGauze is a kernel level network driver that appears to bypass the standard Windows TCP/IP stack
    - **Dsz	DanderSpritz**	Several DanderSpritz specific files such as command descriptions (in XML), and several scripts with DSS (Debug script interface?) / DSI extensions?. They seem to be scripts run by DanderSpritz
    - **Ep	ExpandingPulley**	Listening Post developed in 2001 and abandoned in 2008. Predecessor to DanderSpritz
    - **ExternalLibraries	N/A**	Well..
    - **FlAv	FlewAvenue**	Appears related to DoormanGauze (based on FlAv/scripts/\_FlewAvenue.txt)
    - **GRDO	GreaterDoctor**	Appears to parse / process from GreaterSurgeon (based on GRDO/Tools/i386/GreaterSurgeon_postProcess.py & analyzeMFT.py)
    - **GROK	??**	Appears to be a keylogger (based on Ops/PyScripts/overseer/plugins/keylogger.py)
    - **GRcl	??**	Appears to dump memory from a specific process (based on GRcl/Commands/CommandLine/ProcessMemory_Command.xml)
    - **GaTh	GangsterTheif**	Appears to parse data gathered by GreaterDoctor to identify other (malicious) software that may be installed persistently (based on GaTh/Commands/CommandLine/GrDo_ProcessScanner_Command.xml)
    - **GeZU	GreaterSurgeon**	Appears to dump memory (based on GeZu/Commands/CommandLine/GeZu_KernelMemory_Command.xml)
    - **Gui	N/A**	Resources used by the DanderSpirtz GUI
    - **LegacyWindowsExploits	N/A**	Well..
    - **Ops	N/A**	Contains a lot of awesome tools and python / dss scripts used by DanderSpritz. Deserves a lot of investigation. includes tools to gather data from Chrome, Skype, Firefox (ripper) and gather information about the machine / environment (survey)
    - **Pfree	Passfreely**	Oracle implant that bypasses auth for oracle databases
    - **PaCU	PaperCut**	Allows you to perform operations on file handles opened by other processes
    - **Pc	PeddleCheap**	The main implant (loaded via DoublePulsar) that performs all of these actions and communciates with the C2 (DanderSpirtz)
    - **Pc2.2	PeddleCheap**	Resources for PeddleCheap including different DLLs / configs to call back to the C2
    - **Python	N/A**	Python Libraries / resources being used
    - **ScRe	??**	Interacts with SQL databases (based on ScRe/Commands/CommandLine/Sql_Command.xml)
    - **StLa	Strangeland**	Keylogger (based on StLa/Tools/i386-winnt/strangeland.xsl)
    - **Tasking	N/A**	Handles the collection "tasks" that DanderSpritz has requested on the same (collection of windows, network data, etc)
    - **TeDi	TerritorialDispute**	A plugin used to determine what other (malicious) software may be persistently installed (based on TeDi/PyScripts/sigs.py). Appears to be used to identify other nation states also
    - **Utbu	UtilityBurst**	Appears to be a mechanism for persistence via a driver install unsure (based on UtBu/Scripts/Include/\_UtilityBurstFunctions.dsi)
    - **ZBng	ZippyBang**	Looking at this quickly, it appears to be the NSA's version of Mimikatz. It can duplicate tokens (Kerberos tokens?) and "remote execute commands" as well as logon as users (based on files in ZBng/Commands/CommandLine)
  - Exploits
    - **EARLYSHOVEL** RedHat 7.0 - 7.1 Sendmail 8.11.x exploit
    - **EBBISLAND (EBBSHAVE)** root RCE via RPC XDR overflow in Solaris 6, 7, 8, 9 & 10 (possibly newer) both SPARC and x86.
    - **ECHOWRECKER** remote Samba 3.0.x Linux exploit.
    - **EASYBEE** appears to be an MDaemon email server vulnerability
    - **EASYFUN** EasyFun 2.2.0 Exploit for WDaemon / IIS MDaemon/WorldClient pre 9.5.6
    - **EASYPI** is an IBM Lotus Notes exploit  that gets detected as Stuxnet
    - **EWOKFRENZY** is an exploit for IBM Lotus Domino 6.5.4 & 7.0.2
    - **EXPLODINGCAN** is an IIS 6.0 exploit that creates a remote backdoor
    - **ETERNALROMANCE** is a SMB1 exploit over TCP port 445 which targets XP, 2003, Vista, 7, Windows 8, 2008, 2008 R2, and gives SYSTEM privileges (MS17-010)
    - **EDUCATEDSCHOLAR** is a SMB exploit (MS09-050)
    - **EMERALDTHREAD** is a SMB exploit for Windows XP and Server 2003 (MS10-061)
    - **EMPHASISMINE** is a remote IMAP exploit for IBM Lotus Domino 6.6.4 to 8.5.2
    - **ENGLISHMANSDENTIST** sets Outlook Exchange WebAccess rules to trigger executable code on the client's side to send an email to other users
    - **EPICHERO** 0-day exploit (RCE) for Avaya Call Server
    - **ERRATICGOPHER** is a SMBv1 exploit targeting Windows XP and Server 2003
    - **ETERNALSYNERGY** is a SMBv3 remote code execution flaw  for Windows 8 and Server 2012 SP0 (MS17-010)
    - **ETERNALBLUE is** a SMBv2 exploit for Windows 7 SP1 (MS17-010)
    - **ETERNALCHAMPION** is a SMBv1 exploit
    - **ESKIMOROLL** is a Kerberos exploit targeting 2000, 2003, 2008 and 2008 R2 domain controllers
    - **ESTEEMAUDIT** is an RDP exploit and backdoor for Windows Server 2003
    - **ECLIPSEDWING** is an RCE exploit for the Server service in Windows Server 2008 and later (MS08-067)
    - **ETRE** is an exploit for IMail 8.10 to 8.22
    - **ETCETERABLUE** is an exploit for IMail 7.04 to 8.05
    - **FUZZBUNCH** is an exploit framework, similar to MetaSploit
    - **ODDJOB** is an implant builder and C&C server that can deliver exploits for Windows 2000 and later, also not detected by any AV vendors
    - **EXPIREDPAYCHECK** IIS6 exploit
    - **EAGERLEVER** NBT/SMB exploit for Windows NT4.0, 2000, XP SP1 & SP2, 2003 SP1 & Base Release
    - **EASYFUN** WordClient / IIS6.0 exploit
    - **ESSAYKEYNOTE**
    - **EVADEFRED**
  - Utilities
    - **PASSFREELY** utility which "Bypasses authentication for Oracle servers"
    - **SMBTOUCH** check if the target is vulnerable to samba exploits like ETERNALSYNERGY, ETERNALBLUE, ETERNALROMANCE
    - **ERRATICGOPHERTOUCH**  Check if the target is running some RPC
    - **IISTOUCH** check if the running IIS version is vulnerable
    - **RPCOUTCH** get info about windows via RPC
    - **DOPU** used to connect to machines exploited by ETERNALCHAMPIONS
    - **NAMEDPIPETOUCH** Utility to test for a predefined list of named pipes, mostly AV detection. User can add checks for custom named pipes.
### Password Dumps

- <http://scylla.sh>
- <http://scyllabyeatabumx.onion/>
- <http://52.25.47.112/>
- Mirai
  - <https://github.com/danielmiessler/SecLists/blob/master/Passwords/Malware/mirai-botnet.txt>
  - <https://github.com/securing/mirai_credentials>
- Tomcat
  - <https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt>

## Word-lists

- Parameters
  - <https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt>


## References 

- Conferences, documentaries, podcasts, word-lists, rainbow-tables: <https://infocon.org/>
