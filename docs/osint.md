# OSINT 
## Tools

- Craal (GitHub, Pastebin, S3 Buckets, Protoxin, CertStream): <https://github.com/jaylagorio/craal>
- Semi-automatic OSINT framework and package manager: <https://github.com/kpcyrd/sn0int>
- Discover and extract hostnames providing a large set of target IP addresses: - <https://github.com/SpiderLabs/HostHunter>
- sslyze - Fast and powerful SSL/TLS server scanning library. <https://github.com/nabla-c0d3/sslyze>
- OSINT-SPY - Performs OSINT scan on email/domain/ip_address/organization - <https://github.com/SharadKumar97/OSINT-SPY>
- Vanquish is Kali Linux based Enumeration Orchestrator - <https://github.com/frizb/Vanquish>
```
    | NMap | Hydra | Nikto | Metasploit | | Gobuster | Dirb | Exploitdb | Nbtscan | | Ntpq | Enum4linux | Smbclient | Rpcclient | | Onesixtyone | Sslscan | Sslyze | Snmpwalk | | Ident-user-enum | Smtp-user-enum | Snmp-check | Cisco-torch | | Dnsrecon | Dig | Whatweb | Wafw00f | | Wpscan | Cewl | Curl | Mysql | Nmblookup | Searchsploit | | Nbtscan-unixwiz | Xprobe2 | Blindelephant | Showmount |
```
- LazyRecon - An automated approach to performing recon for bug bounty hunting and penetration testing - <https://github.com/capt-meelo/LazyRecon/>
```
  - Subdomain Enumeration:
    - [Amass](https://github.com/OWASP/Amass)
    - [Subfinder](https://github.com/subfinder/subfinder)
  - Subdomain Takeover:
    - [subjack](https://github.com/haccer/subjack)
  - CORS Configuration:
    - [CORScanner](https://github.com/chenjj/CORScanner)
  - IP Discovery:
    - [Massdns](https://github.com/blechschmidt/massdns)
  - Port Scanning:
    - [Masscan](https://github.com/robertdavidgraham/masscan)
    - [Nmap](https://nmap.org/)
    - [Nmap Bootstrap Stylesheet](https://github.com/honze-net/nmap-bootstrap-xsl/)
  - Visual Recon:
    - [Aquatone](https://github.com/michenriksen/aquatone)
  - Content Discovery:
    - [Dirsearch](https://github.com/maurosoria/dirsearch)
  - Wordlists:
    - [JHaddix's all.txt](https://gist.github.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a)
    - [SecLists' raft-large-words.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-large-words.txt)
```
- pown-recon - A powerful target reconnaissance framework powered by graph theory. - <https://github.com/pownjs/pown-recon>
- Streamline the bug bounty/penetration test reconnaissance phase - <https://github.com/SolomonSklash/chomp-scan>
```
  - Subdomain Discovery (3 different sized wordlists)
    - dnscan
    - subfinder
    - sublist3r
    - massdns + altdns
    - subjack
  - Screenshots (optional)
    - aquatone
  - Port Scanning (optional)
    - masscan and/or nmap
  - Content Discovery (optional) (4 different sized wordlists)
    - ffuf
    - bfac
    - nikto
    - whatweb
  - Wordlists
    - Subdomain Bruteforcing
      - subdomains-top1mil-20000.txt - 22k words - From [Seclists](https://github.com/danielmiessler/SecLists)
      - sortedcombined-knock-dnsrecon-fierce-reconng.txt - 102k words - From [Seclists](https://github.com/danielmiessler/SecLists)
      - huge-200k - 199k words - A combination I made of various wordlists, including Seclists
    - Content Discovery
      - big.txt - 20k words - From [Seclists](https://github.com/danielmiessler/SecLists)
      - raft-large-combined.txt - 167k words - A combination of the raft wordlists in [Seclists](https://github.com/danielmiessler/SecLists)
      - seclists-combined.txt - 215k words - A larger combination of all the Discovery/DNS lists in [Seclists](https://github.com/danielmiessler/SecLists)
      - haddix_content_discovery_all.txt - 373k words - Jason Haddix's [all](https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10/) content discovery list
      - haddix-seclists-combined.txt - 486k words - A combination of the two previous lists
    - Misc.
      - altdns-words.txt - 240 words - Used for creating domain permutations for [masscan](https://github.com/robertdavidgraham/masscan) to resolve. Borrowed from [altdns](https://github.com/infosec-au/altdns/blob/master/words.txt).
      - interesting.txt - 42 words - A list I created of potentially interesting words appearing in domain names.
```

## Email

- TheHarvester
    ```
    theharvester -­‐d cisco.com -­‐b google
    theharvester -­‐d cisco.com -­‐b bing
    ```

## Domain Related Tools

- Dmain Registrations
  - <https://domainbigdata.com>
  - <https://viewdns.info/>
  - <https://pulsedive.com/>
  - <https://www.apnic.net/static/whowas-ui/>
- Archive
  - <https://archive.org/>
- Similar websites
  - <https://similarsites.com/>
  - AltDNS - Generates permutations, alterations and mutations of subdomains and then resolves them: <https://github.com/infosec-au/altdns>
- Subdomains
  - Finds subdomains in google, bing, etc: `python theHarvester.py  -l 500 -b all -d $ip`
  - Sublist3r enumerates subdomains using many search engines and tools: <https://github.com/aboul3la/Sublist3r>
  - SubFinder is a subdomain discovery tool that discovers valid subdomains for websites: <https://github.com/subfinder/subfinder>
  - Knockpy - Enumerate subdomains on a target domain through a wordlist: <https://github.com/guelfoweb/knock>
  - <https://findsubdomains.com/>
  - <https://pentest-tools.com/information-gathering/find-subdomains-of-domain>
  - Abusing Certificate Transparency logs for getting HTTPS websites subdomains: <https://github.com/UnaPibaGeek/ctfr>
- Source Code Analysis
  - https://publicwww.com/
  - https://nerdydata.com/
- Analytic ID cross referencing
  - http://analyzeid.com/
- SSL Certificates
  - https://certdb.com/
  - https://crt.sh/
- Whois API
  - https://www.whoisxmlapi.com/
  - https://www.whoxy.com/

## Subdomain to IP

- Bouncing through an old expired domain. Trusted in all lists.
- W/ a single target domain url, enumerate subdomains.
- Subdomains > IP Addresses > ARIN crawl for more CIDRs.
> https://twitter.com/TinkerSec/status/1097912618663243783


## Services

- <https://www.shodan.io>
  - Find compromised NoSQL systems from Shodan JSON export: <https://gist.github.com/n0x08/39c4fef373d0ac02d61da5d1d3865ce5>
- <https://censys.io/>
- <https://www.zoomeye.org/>
- <https://www.binaryedge.io/>
- <https://viz.greynoise.io/table>
- <https://fofa.so/>
- <https://www.onyphe.io/>
- <https://hunter.io/>
- <https://wigle.net/>
- <https://ghostproject.fr/>
- <https://www.onyphe.io/>
- <https://inteltechniques.com/blog/2018/09/30/breach-data-search-engines-comparison/>

## Web

- AQUATONE - visual inspection of websites across a large amount of hosts - <https://github.com/michenriksen/aquatone>
- EyeWitness - take screenshots of websites, provide some server header info, and identify default credentials if possible: <https://github.com/FortyNorthSecurity/EyeWitness>

## GitHub

- Rapidly search through troves of public data on GitHub - <https://github.com/BishopFox/GitGot> 

## Social

- LikedIn: <https://github.com/vysecurity/LinkedInt>

## Visualizing 

- Visualizing relationships between domains, IPs and email addresses: <https://hackernoon.com/osint-tool-for-visualizing-relationships-between-domains-ips-and-email-addresses-94377aa1f20a>

## OS (VM)

- Buscador Investigative Operating System: <https://inteltechniques.com/buscador/>

## Tool Examples

### ReconNG

General commands:
```
show modules
keys list

workspace add

show schema
show domains
show hosts
add companies
add domains

search reporting
show dashboard
```

Import emails from harvester, etc.:
```
set TABLE contacts
set COLUMN email
set FILENAME united_emails.txt
run
```

Search Showdan for host names:
```
use recon/domains-hosts/shodan_hostname
run
show hosts
show ports
```

Reporting:
```
use report/list
show options
set FILNAME /location/on/file/system
run
```
```
use reporting/html
show options
set CREATOR Pentester
set COMPANY United Airlines
```

## References

### New References
- Exploiting Vulnerabilities Through Proper Reconnaissance: <https://docs.google.com/presentation/d/1xgvEScGZ_ukNY0rmfKz1JN0sn-CgZY_rTp2B_SZvijk/edit#slide=id.g4052c4692d_0_0>
- Recon My Way: <https://github.com/ehsahil/recon-my-way>

### References
- List of s3 leaks: <https://github.com/nagwww/s3-leaks>
- OSINT Framework: <https://osintframework.com/>
- RiskIQ Community Edition: digital threat hunters and defenders free access to our comprehensive internet data to hunt digital threats: <https://www.riskiq.com/products/community-edition/>
- Deleted content: <https://osintcurio.us/2019/02/12/osint-on-deleted-content/>
- Week in OSINT #2019–06: <https://medium.com/week-in-osint/week-in-osint-2019-06-8a13feb018a8>
- SANS Webcast: OSINT for Pentesters Finding Targets and Enumerating Systems: <https://www.youtube.com/watch?v=eHOMGUTi9yo&feature=youtu.be>
- <https://ahrefs.com/blog/google-advanced-search-operators/>
- <https://null-byte.wonderhowto.com/how-to/hack-like-pro-reconnaissance-with-recon-ng-part-1-getting-started-0169854/>
- <http://securenetworkmanagement.com/recon-ng-tutorial-part-1/>
- <http://securenetworkmanagement.com/recon-ng-tutorial-part-2/>
- <http://securenetworkmanagement.com/recon-ng-tutorial-part-3/>
