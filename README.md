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
    
    Author = G0urmetD
    version = 1.3.5
    
[INFO] Here is some help ...
Usage: Miscon.ps1 -d <domain> [-u <username>] [-p <password>] [-h]
Parameters:
-d, -domain              Defines the Active Directory domain. [required]
-u, -username            Defines the Active Directory username. [optional]
-p, -password            Defines the Active Directory user password. [optional]
-i, -info                Starts Basic Domain Information Enumeration [Optional]
-b, -basic               Starts searching for basic misconfigurations [Optional]
```

## Examples
```powershell
.\miscon.ps1 -d <domain> -info
.\miscon.ps1 -d <domain> -basic

.\miscon.ps1 -d <domain> -info -basic
```
