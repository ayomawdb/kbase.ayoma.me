## Defense 

- Use unique and strong local admin account passwords
- Use Microsoft LAPS to automate local admin password changes
- KB2871997 to disallow local account logon across the network 
- Limit workstation to workstation communication
- Implement network segmentation
- Never run services with domain-admin privileged accounts on workstations (avoid dumping from LSASS)
- Install patch (), so that LSASS will not store plain text password 
- Done't use unconstrained delegation (this stores user's delegated TGS in LSASS). Only use constrained delegation.
- Disable delegation for admin accounts (Check: Account is sensitive and cannot be delegated).
  - Detect based on delegation events.