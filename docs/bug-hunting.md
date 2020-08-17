## Bounty Programs

- [ZERODIUM is the leading exploit acquisition platform for premium zero-days and advanced cybersecurity capabilities](https://zerodium.com/program.html)
- [FedBounty - A Federally Sponsored National Bug Bounty Program](https://www.secjuice.com/fedbounty-national-bug-bounty-program/)

## Bounty Guides

- [Subdomain takeover](https://0xpatrik.com/second-order-bugs/)
- [Hitchhiker’s Guide to Bug Bounty Hunting Throughout the Galaxy. v2 by Nick Jenkins](https://hakin9.org/the-hitchhikers-guide-to-bug-bounty-hunting-throughout-the-galaxy-v2)
- [Guide to Responsible Disclosure and Bug Bounty](https://blog.detectify.com/2018/02/27/guide-responsible-disclosure/)

## Educational Content Connections

- [Google Bughunter University](https://sites.google.com/site/bughunteruniversity/)
- [BugCroud University](https://github.com/bugcrowd/bugcrowd_university)
- [Getting started in bugbounties](https://www.bugbountynotes.com/getting-started)

## Writeups

### Writeup Collections

- [https://pentester.land/list-of-bug-bounty-writeups.html](https://pentester.land/list-of-bug-bounty-writeups.html)

### Facebook

- [Disclosing page members](https://medium.com/@tnirmalz/facebook-bugbounty-disclosing-page-members-1178595cc520)

### Google writeups

- [$7.5k Google Cloud Platform organization issue](https://www.ezequiel.tech/2019/01/75k-google-cloud-platform-organization.html)

## Techniques 

- Static analysis of code involving user-input 
- Look for unsafe usages of language features (check `languages` file)
- Look for `movsx`  (sign extension vulnerability)
- Fuzzing
  - The Art of Software Security Assessment: Identifying and Preventing Software Vulnerabilities (Addison- Wesley, 2007).
  - Michael Sutton, Adam Greene, and Pedram Amini’s Fuzzing: Brute Force Vulnerability Discovery (Addison-Wesley, 2007)
- Memory errors
  - Using memory it does not own (e.g., NULL pointer dereferences)
  - Using more memory than has been allocated (e.g., buffer overflows)
  - Using uninitialized memory (e.g., uninitialized variables)
    - Daniel Hodson, “Uninitialized Variables: Finding, Exploiting, Auto-mating” (presentation, Ruxcon, 2008), <http://felinemenace.org/~mercy/slides/RUXCON2008-UninitializedVariables.pdf>
  - Using faulty heap-memory management (e.g., double frees)

## Vulnerability Market

- Pedram Amini, “Mostrame la guita! Adventures in Buying Vulnerabili- ties,” 2009, <http://docs.google.com/present/view?id=dcc6wpsd_20ghbpjxcr>
- Charlie Miller, “The Legitimate Vulnerability Market: Inside the Secretive World
of 0-day Exploit Sales,” 2007, <http://weis2007.econinfosec.org/papers/29.pdf> 
- iDefense Labs Vulnerability Contribution Program, <https://labs.idefense.com/vcpportal/login.html>
- TippingPoint’s Zero Day Initiative, <http://www.zerodayinitiative.com/>.
