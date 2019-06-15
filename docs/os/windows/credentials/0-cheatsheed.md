# Cheatsheet

## LM hashes
- Password longer than 7 is split and each half hashed separately
- Passwords are converted into uppercase
- No salt
- Empty LM hash
```
AAD3B435B51404EE
AAD3B435B51404EEAAD3B435B51404EE
```
## NTLM hashes

## Dumping hashes
- Cannot copy SAM when sys is in use

## Capturing Hashes

### Responder
### Inveigh
### Impacket's smbserver.py

## Attack Patterns

### Pass the Hash

Auth using username and NTLM hash (since NTLM and LM hashes are not salted)

- Replace "no password" in dump wih empty LM hash
- Copy admins dumped hash (LM:NTML)
- export SMBHASH=LM:NTML
- pth-winexe -U administrator% //ip cmd

#### pth-winexe
```
pth-winexe
-U jeeves/Administrator%aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
//10.10.10.63 cmd
```

### RDP Password Brute-forcing 
```
ncrack -v -f --user administrator -P password.txt rdp://ip,CL=1
```

### LSASS

## Attack Techniques 

### DPAPI Backup Key

- Access to secret keys of all users in a domain (certificate, private key, etc.)
- Obtaining the never changing DPAPI master key
- In a domain setup, all master keys are required to decrypt the keys.
  - All master keys are protected using  one never renewed  key. 
  - Backup key protocol can be used (Mimikatz) to get this key from DC.

### Skeleton Key
- Actors can use a password of their choosing to authenticate as any user.

- Skeleton Key is deployed as an in-memory patch on a victim's AD domain controllers to allow the threat actor to authenticate as any user, while legitimate users can continue to authenticate as normal. 

  

>  Ref: https://www.secureworks.com/research/skeleton-key-malware-analysis](https://www.secureworks.com/research/skeleton-key-malware-analysis)



> When run, Skeleton Key performs the following tasks:
>
> 1. Check for one of the following compatible 64-bit Windows versions. The malware is not compatible with 32-bit Windows versions or with Windows Server versions beginning with Windows Server 2012 (6.2).
>    - 6.1 (Windows 2008 R2)
>    - 6.0 (Windows Server 2008)
>    - 5.2 (Windows 2003 R2)
> 2. Use the SeDebugPrivilege function to acquire the necessary administrator privileges to write to the Local Security Authority Subsystem Service (LSASS) process. This process controls security functions for the AD domain, including user account authentication.
> 3. Enumerate available processes to acquire a handle to the LSASS process.
> 4. Obtain addresses for the authentication-related functions that will be patched:
>    - CDLocateCSystem — located in cryptdll.dll
>    - SamIRetrieveMultiplePrimaryCredentials — located in samsrv.dll
>    - SamIRetrievePrimaryCredentials — located in samsrv.dll
> 5. Perform OS-specific adjustments using the global variable set during the compatibility check in Step 1.
> 6. Use the OpenProcess function to acquire a handle to the LSASS process.
> 7. Reserve and allocate the required memory space to edit and patch the LSASS process's memory.
> 8. Patch relevant functions based on the operating system:
>    - CDLocateCSystem (all compatible Windows versions)
>    - SamIRetrieveMultiplePrimaryCredentials (only Windows 2008 R2 (6.1))
>    - SamIRetrievePrimaryCredentials (all compatible Windows versions other than Windows 2008 R2 (6.1))
>
> 
>
> Skeleton Key performs the following steps to patch each function:
>
> 1. Call the VirtualProtectEx function to change the memory protection to allow writing to the required memory allocations (PAGE_EXECUTE_READWRITE, 0x40). This step allows the function's code to be updated in memory.
> 2. Call the WriteProcessMemory function to change the address of the target function to point to the patched code. This change causes calls to the target function to use the patch instead.
> 3. Restore the original memory protection by calling VirtualProtectEx with the original memory protection flags. This step is likely to avoid suspicious writable and executable memory allocations.

### Manipulating SID 

- sidHistory can be used to manipulate SID and become domain admin
- Use SID of the DC to look ad domain admin
- Use DCSync to get more information  

## Windows Version Dependent Information

### Windows 2000
- LSASS contains
  - Plain NTLM / LM hashes
  - Kerberos keys, tickets, session keys, passwords (if not consumed already)
- Passwords encrypted in memory using 1 byte key (XOR)
  - Key is stored in a secret structure
- [Tool] MimiLove (not in Mimikatz )

### Windows XP/2003

- WDigest provider to auth to Web/SASL/LDAP - RFC2617
- Password constantly stays in memory
- LSA SSO secrets protected by LsaEncryptMemory and unencrypted by LsaUnprotectMemory 
  - RC4 DESx
- Key and IV are stored near the secret in LSASS process
- TsPks (CredSSP) provider can be added manually in XP
  - Terminal server single sign on
  - Credential delegation for terminal server/PowerShell/Double hop, etc.
- LiveSSP - For using live account to logon to windows 

### Windows Vista/7

- TsPkg (CredSSP support) is available by default
- Several passwords are constantly in memory
- LSA SSO secrets protected by LsaEncryptMemory and unencrypted by LsaUnprotectMemory
  - 3DES AES
- Key and IV are stored near the secret in LSASS process

### Windows 8/8.1

- Clear text domain passwords in Vault
  - When using PIN, Picture or Fingerprint to authenticate 
  - Offline access is possible
- Pass the hash, over pass the hash and pass the ticket for RDP

### Windows 8.1

- WDigest is off by default.
- No password in memory by default.
- LSA login session cache cleaner 
- Restricted admin mode for RDP
  - Avoid credentials from getting sent to server 
  - Pass the hash, over pass the hash and pass the ticket for RDP (with CredSSP)
- LSA protection
  - LSASS is a protected process. No memory access provided. 
  - Can be bypassed by:
    - A driver
    - Another protected process 
- Protected Users security group
  - No NTLM, WDigest, CredSSP, delegation or SSO
  - Strengthen eKerberos only
- KB2975625 - Restricted admin is disabled by default

### Windows 10 

- VMS introduce for enterprise users
  - Use Crypto HSM approach 
  - When Windows Credential Guard is enabled:
    - NTLM hash of the password stored in the memory in "secure world", encrypted with a "session-key".
    - User will get a blob.
    - When authenticating, user sends the blob with NTLM challenge.
    - Secure world will do the hashing operation and create the NTML challenge response and send the response to the normal world.
    - In Kerberos, process is same (secure-world maintain more keys)
    - Limitations 
      - TGS session key is not protected (TGT is protected)
      - Not available in VMs and not enabled by default 
    - More to protect:
      - DPAPI 
      - SAM / DSRM
      - PAC signature

## References
- Extracting User Password Data with Mimikatz DCSync: https://blog.stealthbits.com/extracting-user-password-data-with-mimikatz-dcsync/
- Pwning with Responder – A Pentester’s Guide: https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/
