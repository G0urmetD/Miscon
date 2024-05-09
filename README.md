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
    version = 1.6.12

[INFO] Here is some help ...
Usage: Miscon.ps1 -d <domain> [-u/-username <username>] [-p/-password <password>] [-h] [-i/-info] [-b/-basic] [-q/-quick] [-pndc] [-pnou -sb <searchbase>] [-dacl -u <username> -p <password>]

Parameters:
------------------------------------------------------------------------------------------------------------------
-d, -domain              Defines the Active Directory domain. [required]
-i, -info                Starts Basic Domain Information Enumeration [Optional]
-b, -basic               Starts searching for basic misconfigurations [Optional]
-q, -quick               Starts searching for quickwins like AS-REP Roasting/Kerberoastable Accounts/LLMNR
-pndc, -pndc             Checks if the spooler service is running on the domain controllers. [Optional]
-pnou, -pnou             Checks if the spooler service is running on servers in target OU. [Optional]
      -sb, -searchbase         Defines ou path for pnou parameter. [Optional]
-dacl, -dacl             Checks for custom domain acls on not built-in objects. [Optional]
      -u, -username            Defines the Active Directory username. [optional]
      -p, -password            Defines the Active Directory user password. [optional]
```
