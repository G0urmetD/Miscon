<img src="guidance.png" alt="miscon" width="200" height="200"/>

# Miscon
- find Active Directory misconfigurations (quickwins for Pentesting)
- Domain password spray
- Local Admin check

## Functions
### Find-Misconfigurations
Find misconfigurations in an active directory.

```PowerShell
-Domain = defines the domain
-Type = defines the type (default = light | other types: extended, quickwins)
```

```PowerShell
Find-Misconfigurations -Domain "test.local"
Find-Misconfigurations -Domain "test.local" -Type "light"
Find-Misconfigurations -Domain "test.local" -Type "extended"
Find-Misconfigurations -Domain "test.local" -Type "quickwins"
```

### DomainPasswordSpray
All Credits goes to dafthack, copied his DomainPasswordSpray PowerShell script, because it is awesome.
Perform domain password spray attacks.

```PowerShell
# single password spray
Invoke-DomainPasswordSpray -Password Spring2017

# uses userlist and passwordlist, creating outfile
Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt

# using userlist and one password, creating outfile
Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -Password Summer2017 -OutFile sprayed-creds.txt

# creating userlist out of the domain
Get-DomainUserList -Domain domainname -RemoveDisabled -RemovePotentialLockouts | Out-File -Encoding ascii userlist.txt
```

### Invoke-CheckLocalAdmin
Function to check a user against a list of hosts, if the user has local admin privileges.

```PowerShell
Invoke-CheckLocalAdmin -user john -hosts C:\Users\user1\Downloads\hosts.txt
```
