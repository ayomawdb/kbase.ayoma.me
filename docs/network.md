## Quick Reference

**Cheat Sheets**

- Nmap: https://blogs.sans.org/pen-testing/files/2013/10/NmapCheatSheetv1.1.pdf
- Wireshark: [https://packetlife.net/media/library/13/Wireshark_Display_Filters.pdf](https://packetlife.net/media/library/13/Wireshark_Display_Filters.pdf)
- TcpDump: [https://packetlife.net/media/library/12/tcpdump.pdf](https://packetlife.net/media/library/12/tcpdump.pdf)
- Netcat: [https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf](https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf)
- Ncat: [https://medium.com/@pentest_it/ncat-cheatsheet-ddc5f07d8533](https://medium.com/@pentest_it/ncat-cheatsheet-ddc5f07d8533)
- Scapy: [https://blogs.sans.org/pen-testing/files/2016/04/ScapyCheatSheet_v0.2.pdf](https://blogs.sans.org/pen-testing/files/2016/04/ScapyCheatSheet_v0.2.pdf)

**Quick Reference**

- [How to Find Your Public IP Address on Linux Command Line](https://www.putorius.net/find-public-ip-address-linux-command-line.html): `curl https://ipaddr.pub`
- MAC to IPv6: <https://ben.akrin.com/?p=1347>
  - take the mac address: for example `52:74:f2:b1:a8:7f`
  - throw `ff:fe` in the middle: 52:74:f2:`ff:fe`:b1:a8:7f
  - reformat to IPv6 notation `5274:f2ff:feb1:a87f`
  - convert the first octet from hexadecimal to binary: `52` -> `01010010`
  - invert the bit at index 6 (counting from 0): `01010010` -> `01010000`
  - convert octet back to hexadecimal: `01010000` -> `50`
  - replace first octet with newly calculated one: `5074:f2ff:feb1:a87f`
  - prepend the link-local prefix: `fe80::5074:f2ff:feb1:a87f`
  - <https://stackoverflow.com/questions/27693120/convert-from-mac-to-ipv6>    
    ```cpp
    format_eui_64() {
        local macaddr="$1"
        printf "%02x%s" $(( 16#${macaddr:0:2} ^ 2#00000010 )) "${macaddr:2}" \
            | sed -E -e 's/([0-9a-zA-Z]{2})*/0x\0|/g' \
            | tr -d ':\n' \
            | xargs -d '|' \
            printf "%02x%02x:%02xff:fe%02x:%02x%02x"
    }
    ```
- HTTP Request with `/dev/tcp`
    ```bash
    exec 3<>/dev/tcp/(INTERNAL IP ADDRESS)/80
    echo -e "GET / HTTP/1.1\r\nHost: (INTERNAL IP ADDRESS)\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (X11;Linux x86_64...) Gecko/20100101 Firefox/60.0\r\n\r\n" >&3
    cat <&3
    ```
- TCP Flag Key: <http://rapid.web.unc.edu/resources/tcp-flag-key/>
- Network Discovery
    ```
    nmap -sP 192.168.1.1-255
    ettercap -T -i eth0 ///
    netdiscover -i ens33
    ```
- IPv6 
    ```
    ping (TARGET IP ADDRESS)
    arp -a
    ```

## Port Scanning

- FPing: `for ip in $(seq 1 254);do fping 10.11.1.$ip >> fping.txt;done;grep alive ./fping.txt`
- Nc:
  - `for ip in $(seq 1 5); do nc -nvv -z 192.168.1.$ip 80 &>> /tmp/ncscan.txt done`
  - `nc -z -v (TARGET IP ADDRESS) 1-1024 2>/dev/stdout| grep -v refused`
- ARP ping: `nmap -sP -PR 10.11.1.0/24 -oG nmap-arp.txt`
- Ping: `for ip in $(seq 1 254);do ping -c 1 192.168.1.$ip | grep "bytes from" | cut -d" " -f4 | cut -d":" -f1 & done`
- /dev/tcp: `for port in $(seq 1 65530); do (echo $port > /dev/tcp/$target/$port && printf "[!] $port is open.\n") 2>/dev/null done`
- Port monitor 
    ```bash
    watch -n1 nc -w1 -nvz 192.168.1.23 123
    # -w1: timeout 1 sec, -n: no reverse lookup, -v: verbose, -z: no IO, act as a scanner
    ```
- Nmap: Evade Firewall
  - `-sA` - TCP ACK Scan
  	- Because of the ACK packets the firewall cannot create the log
  	- Firewalls treat ACK packet as the response of the SYN packet
  		- Open port (few ports in the case of the firewall)
      - Closed port (most ports are closed because of the firewall)
      - Filtered (Nmap is not sure whether the port is open or not)
      - Unfiltered (Nmap can access the port but is still confused about the open status of the port)
  - `-sW` - TCP Window Scan
  	- Designed to differentiate between open and closed ports instead of showing unfiltered
  	- Does not open any active session with the target computer
  	- Send ACK packets and receive a single RST packet in response
  - `-f`, `-ff` - Fragment Packets
  - `-spoof-mac Cisco` - Spoof MAC
  - `-scan_delay` - control the delay between each and every request
  - `-host-timeout`
- Types of port scans
  - TCP Connect Scan: `nc -nvv -w 1 -z <ip> <port-range>`
    - Full 3 way handshake
  - SYN / Stealth Scan
    - Send SYN
    - SYN-ACK means open
    - RST means closed
  - UDP Scanning: `nc -nv -u -z -w 1 <ip> <port-range>`
    - ICMP port unreachable means closed
    - No response means open
- Port Knocking: `for x in 1111, 2222, 3333; do nmap -Pn --host_timeout 201 --scan-delay 0.2 --max-retries 0 -p $x <IP>; done`
  - Look for: `knockd`
  - Configured at: `​/etc/knockd.conf​`
- Scanning Methods
  - All TCP and UDP fast scan:
    ```bash
    masscan -p1-65535,U:1-65535 <IP> --rate=1000 -e tun0 -p1-65535,U:1-65535 > ports
    ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
    nmap -Pn -sV -sC -sU -sT -p$ports <IP>
    ```
  - Quick all TCP scan using Nmap only:
    ```bash
    ports=(nmap -p- --min-rate=1000 -T4 <IP> | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
    nmap -Pn -sV -sC -sU -sT -p$ports <IP>
    ```
  - Quick all TCP and UDP scan using Nmap only:
    ```bash
    ports=(nmap -p- --min-rate=1000 -T4 <IP> | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
    nmap -Pn -sV -sC -sU -sT -p$ports <IP>
    ```
    ```bash
    nmap -sS -T5 -A -f -v IP
    nmap -n -Pn -sV --version-all --open -sC -oA [target] --stats-every 120
    nmap -T4 -sV -sC -Pn [box ip] -oA [box_name]_initial_scan
    ```
- Vulnerability Scanning
  - Nmap
    ```bash
    nmap -v -p 80 --script http-vuln-cve2010-2861 <ip>
    nmap -v -p 80 --script all <ip>
    nmap -v -p 80 -sC <ip>
    nmap -v -p 80 --script default,safe <ip>
    ```
  - OpenVAS
    ```
    openvas-setup
    https://ip:9392
    ```
## Tools

- Inject code and spy on wifi users: <https://github.com/DanMcInerney/LANs.py>
- Collection of PowerShell network security scripts for system administrators: <https://github.com/thom-s/netsec-ps-scripts>
- [CyberScan: Network's Forensics ToolKit](https://github.com/medbenali/CyberScan)
- Sparta: <https://github.com/SECFORCE/sparta>
- BetterCap - Swiss army knife for network attacks and monitoring: <https://www.bettercap.org/>
  - Pwning WPA/WPA2 Networks With Bettercap and the PMKID Client-Less Attack: <https://www.evilsocket.net/2019/02/13/Pwning-WiFi-networks-with-bettercap-and-the-PMKID-client-less-attack/#.XGRV3mo06jA.twitter>
- Nmap 
  - Port Related Information: `/usr/share/nmap/nmap-servies`
  - ICMP (Ping) Sweep:
    ```
    nmap -sn <pi-rage>
    nmap -sn <ip-range> -oG filename (grepable format)
    ```
  - Sweep TCP/UDP ports: `nmap -p 80 <ip-range> -oG filename` 
  - Sweep full network for top ports: `nmap -sT -A --top-ports=20 <ip-range> -G filename`
  - Script engine: `ls -l /usr/share/nmap/scripts | grep smb`
  - Important flags
    - `-O` for OS Fingerprinting
    - `-sV` for banner grabbing
  - Netstat
    - Kernel IP routing table: `netstat -nr`
    - Listening ports: `netstat -lp` `netstat -lvnp`
  - Netcat 
    - Cheat sheet: <https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf>
    - General Commands 
      - Listen on port 567/TCP: `nc -l -p 567` 
      - Connecting to 567 of 1.2.3.4: `nc 1.2.3.4 5676` 
      - Pipe a text file to the listener: `cat infile | nc 1.2.3.4 567 -q 10`
      - Have the listener save a received text file: `nc -l -p 567 > textfile`
      - Transfer a directory: 
        - Reciever: `nc -l -p 678 | tar xvfpz`
        - Sender: `tar zcfp - /path/to/directory | nc -w 3 1.2.3.4 678` 
      - Send a message to your syslog server (the <0> means emerg): `echo '<0>message' | nc -w 1 -u syslogger 514` 
      - Setup a remote shell listener: 
        - `nc -v -e '/bin/bash' -l -p 1234 -t`
        - `nc l p 1234 e "c:\windows\system32\cmd.exe"` 
      - Make an HTTP request: `echo -e "GET http://www.google.com HTTP/1.0nn" | nc -w 5 www.google.com 80` 
      - One-page webserver: `cat homepage.txt | nc -v -l -p 80` 
    - General Options 
      - Use IPv4 addressing only: `nc -4 [options] [host] [port]` 
      - Use IPv6 addressing only: `nc -6 [options] [host] [port]` 
      - UDP instead of TCP: `nc -u [options] [host] [port]` 
      - Listen for an incoming connection: `nc -l [host] [port]` 
      - Continue listening after client has disconnected: `nc -k -l [host] [port]` 
      - No DNS lookups: `nc -n [host] [port]` 
      - Use specific source port: `nc -p [source port] [host] [port]` 
      - Use source IP: `nc -s [source ip] [host] [port]` 
      - Apply 'n' second timeout: `nc -w [timeout] [host] [port]` 
      - Verbose output: `nc -v [host] [port]` 
    - Port Scanning 
      - Scan a single TCP port: `nc -zv hostname.com 80` 
      - Scan a range of ports: `nc -zv hostname.com 80-84` 
      - Scan multiple ports: `nc -zv hostname.com 80 84` 
    - Other 
      - One page web server: `while : ; do ( echo -ne "HTTP/1.1 200 OK\r\nContent-Length: $(wc -c <index.html)\r\n\r\n" ; cat index.html; ) | nc -l -p 8080 ; done`
      - Proxy: `mknod backpipe p ; nc -l [proxy port] < backpipe | nc [destination host] [destination port] > pipe`
      - Wrap readline history library (support up arrow, etc):`rlwrap nc -t remotehost 23`
    - References:
      - <https://kapeli.com/cheat_sheets/Netcat.docset/Contents/Resources/Documents/index>
      - <http://workrobot.com/sysadmin/security/netcat_cheatsheet.html>

## Techniques 

### Domain Fronting

**Tools**

- Psiphon: https://www.psiphon3.com/en/index.html
- Meek: https://trac.torproject.org/projects/tor/wiki/doc/AChildsGardenOfPluggableTransports#meek

**References**

- Introduction: https://www.andreafortuna.org/cybersecurity/privacy/domain-fronting-in-a-nutshell/
- Usage in APT29: https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html
- Azure (Hardening Your Azure Domain Front): https://medium.com/@rvrsh3ll/hardening-your-azure-domain-front-7423b5ab4f64
- A 101 on Domain Fronting: https://digi.ninja/blog/domain_fronting.php
- Domain Fronting with CloudFront: https://digi.ninja/blog/cloudfront_example.php

### Traffic Analysis

- Accounting Traffic 
    ```bash
    #!/bin/bash
    # Reset counters and iptables rules
    iptables -Z && iptables -F
    # Measure incoming traffic from lab machine
    iptables -I INPUT 1 -s 192.168.1.23 -j ACCEPT
    # Measure outgoing traffic to lab machine
    iptables -I OUTPUT 1 -d 192.168.1.23 -j ACCEPT
    ```
    ```
    watch -n 1 iptables -nvL
    ```
- Using a Capture: `aircrack-ng captured.cap​`
- Netcap - A framework for secure and scalable network traffic analysis: <https://github.com/dreadl0ck/netcap>
- PCAP Samples:
  - Netresec: <https://www.netresec.com/?page=pcapfiles>
  - Malware Traffic Analysis: <https://www.malware-traffic-analysis.net/>
  - Packettotal (Just like virustotal but for PCAP Analysis): <https://packettotal.com/>
  - <https://wiki.wireshark.org/SampleCaptures>
- PA Toolkit (Pentester Academy Wireshark Toolkit) - PA Toolkit is a collection of traffic analysis plugins to extend the functionality of Wireshark from a micro-analysis tool and protocol dissector to the macro analyzer and threat hunter: <https://github.com/pentesteracademy/patoolkit>
-  CapAnalysis: <https://drive.google.com/uc?authuser=0&id=1Lf8yU7alFZdRlT6WstKjngN2RAp-1jG8&export=download>
- Netsh (Windows)   
    ```
    netsh trace show capturefilterhelp
    netsh trace show scenarios
    netsh trace show globalkeywordsandlevel
    ```
    ```
    netsh trace start capture=yes IPv4.Address=192.168.122.2
    netsh trace start scenario=InternetClient,InternetServer,NetConnection globalLevel=win:Verbose capture=yes report=yes traceFile=C:\temp\trace\trace001.etl
    netsh trace stop
    ```
- Use Microsoft Network Monitor 3.4 to view: <https://www.microsoft.com/en-us/download/details.aspx?id=4865>
- Convert to PAC from: <https://github.com/microsoft/etl2pcapng>
- Use powershell to convert:
    ```powershell
    $s = New-PefTraceSession -Path “C:\output\path\spec\OutFile.Cap” -SaveOnStop
    $s | Add-PefMessageProvider -Provider “C:\input\path\spec\Input.etl”
    $s | Start-PefTraceSession
    ```  
- tcpdump to show HTTP request/response headers
  - <https://serverfault.com/questions/504431/human-readable-format-for-http-headers-with-tcpdump>
    ```bash
    sudo tcpdump -A -s 10240 'tcp port 4080 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' | egrep --line-buffered "^........(GET |HTTP\/|POST |HEAD )|^[A-Za-z0-9-]+: " | sed -r 's/^........(GET |HTTP\/|POST |HEAD )/\n\1/g'
    ```
    ```bash
    sudo stdbuf -oL -eL /usr/sbin/tcpdump -A -s 10240 "tcp port 4080 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)" | egrep -a --line-buffered ".+(GET |HTTP\/|POST )|^[A-Za-z0-9-]+: " | perl -nle 'BEGIN{$|=1} { s/.*?(GET |HTTP\/[0-9.]* |POST )/\n$1/g; print }'
    ```
- tcpdump
    ```
    tcpdump -i eth1  -s 0 port not 22
    tcpdump -i eth1  -s 0 port not 22 and port not 53
    tcpdump -i eth1 port not 22 and host 1.2.3.4
    ```
    
## Defense 

- Phishing Blacklist: <https://www.phishing.army/>

## References

- [Beginner's Guide to Impacket Tool kit (Part 1)](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
- Let's code a TCP/IP stack, 1: Ethernet & ARP: <http://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp/>
- Let's code a TCP/IP stack, 2: IPv4 & ICMPv4: <http://www.saminiir.com/lets-code-tcp-ip-stack-2-ipv4-icmpv4/>
- Let's code a TCP/IP stack, 3: TCP Basics & Handshake: <http://www.saminiir.com/lets-code-tcp-ip-stack-3-tcp-handshake/>
- Practical man-in-the-middle attacks in computer networks - Matˇej Plch: <https://is.muni.cz/th/s8uf2/thesis.pdf>
