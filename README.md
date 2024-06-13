<img src="guidance.png" alt="miscon" width="200" height="200"/>

# Miscon
Modular PowerShell Tool to display domain information, find basic & advanced misconfigurations and other cool stuff.

```powershell
    ___  ____
    |  \/  (_)
    | .  . |_ ___  ___ ___  _ __  
    | |\/| | / __|/ __/ _ \| '_ \ 
    | |  | | \__ \ (_| (_) | | | |
    \_|  |_/_|___/\___\___/|_| |_|

    

        Author:     G0urmetD
        Version:    2.0
    
======================================== { Description } =============================================
MisconPE is a tool to find misconfigurations, information or vulnerabilities in an Active Directory.
======================================== { Parameters } ==============================================

        -h, -help                   Show help function.
        -d, --domain                Defines the target domain.

        -u, --username              Defines the username, necessary for some checks.
        -p, --password              Defines the password. [SecureString]

        -all                        Run all checks of the tool.
        -quickwins                  Run quickwins checks.
        -i, --info                  Shows Domain information.
        -b, --basic                 Run basic misconfiguration checks.

        -kerberoast                 Scans for kerberoastable accounts in the domain.
        -asrep                      Scans for asrep roastable accounts in the domain.
        -dcsync                     Scans for dcsync privileges.
        -llmnr                      Check if LLMNR is activated in the domain.

        -dacl, --domainACL          Checks for custom domain acls on not built-in objects.
        -gpo, --groupPolicy         Enumerate domain GPOs.
        -adcs, --adcsTemplates      Enumerates ADCS tempaltes.
            -fg, --faineGrained         Enumerates ADCS templates fine grained with more information about the templates.
        -jp, --juicyPorts           Fetch computer objects out of active directory and scan for juicy ports (3389, 5985, 5986, 80, 443, 8080, 8443, 22, 2222, 1433).
        -pnou, --printNightmareOU   Checks if the spooler service is running on servers in target OU.
            -sb, --searchBase           Defines ou path for pnou parameter.
        -pndc, --printNightmareDC   Checks if the spooler service is running domain controllers. [Username & Password required]
```
