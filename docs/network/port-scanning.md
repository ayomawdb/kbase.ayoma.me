# Port Scanning

FPing:
```
for ip in $(seq 1 254);do fping 10.11.1.$ip >> fping.txt;done;grep alive ./fping.txt
```

Nc:
```
for ip in $(seq 1 5);
	do nc -nvv -z 192.168.1.$ip 80 &>> /tmp/ncscan.txt
done
```

ARP ping:
```
nmap -sP -PR 10.11.1.0/24 -oG nmap-arp.txt
```

Ping:
```
for ip in $(seq 1 254);do
        ping -c 1 192.168.1.$ip | grep "bytes from" | cut -d" " -f4 | cut -d":" -f1 &
done
```
## Evade Firewall

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

## Types of port scans

### TCP Connect Scan
- Full 3 way handshake
```
nc -nvv -w 1 -z <ip> <port-range>
```

### SYN / Stealth Scan
- Send SYN
- SYN-ACK means open
- RST means closed

### UDP Scanning
- ICMP port unreachable means closed
- No response means open
```
nc -nv -u -z -w 1 <ip> <port-range>
```

## Port Knocking
```
for x in 1111, 2222, 3333; do nmap -Pn --host_timeout 201 --scan-delay 0.2 --max-retries 0 -p $x <IP>; done
```

Look for: `knockd`
Configured at: `​/etc/knockd.conf​`

## Scanning Methods

All TCP and UDP fast scan:
```
masscan -p1-65535,U:1-65535 <IP> --rate=1000 -e tun0 -p1-65535,U:1-65535 > ports
ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
nmap -Pn -sV -sC -sU -sT -p$ports <IP>
```

Quick all TCP scan using Nmap only:
```
ports=(nmap -p- --min-rate=1000 -T4 <IP> | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -Pn -sV -sC -sU -sT -p$ports <IP>
```

Quick all TCP and UDP scan using Nmap only:

```
ports=(nmap -p- --min-rate=1000 -T4 <IP> | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -Pn -sV -sC -sU -sT -p$ports <IP>
```

```
nmap -sS -T5 -A -f -v IP
nmap -n -Pn -sV --version-all --open -sC -oA [target] --stats-every 120
nmap -T4 -sV -sC -Pn [box ip] -oA [box_name]_initial_scan

```
