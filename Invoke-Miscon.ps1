<#
.DESCRIPTION
    MisconPE is a tool to find misconfigurations, information or vulnerabilities in an Active Directory.
#>

param(
    [Parameter(HelpMessage = "Shows some help for young padawans.")]
    [Alias('h')]
    [switch]$help,

    [Parameter(HelpMessage = "Defines the target domain.")]
    [Alias('d')]
    [string]$domain,

    [Parameter(HelpMessage = "Run all checks of the tool.")]
    [switch]$all,

    [Parameter(HelpMessage = "Run quickwins checks.")]
    [switch]$quickwins,

    [Parameter(HelpMessage = "Shows domain information.")]
    [Alias('i')]
    [switch]$info,

    [Parameter(HelpMessage = "Shows domain information.")]
    [Alias('b')]
    [switch]$basic,

    [Parameter(HelpMessage = "Scans for kerberoastable accounts in the domain.")]
    [switch]$kerberoast,

    [Parameter(HelpMessage = "Scans for asrep roastable accounts in the domain.")]
    [switch]$asrep,

    [Parameter(HelpMessage = "Scans for dcsync privileges.")]
    [switch]$dcsync,

    [Parameter(HelpMessage = "Check if LLMNR is activated in the domain.")]
    [switch]$llmnr,

    [Parameter(HelpMessage = "Checks for custom domain acls on not built-in objects.")]
    [Alias('dacl')]
    [switch]$domainACL,

    [Parameter(HelpMessage = "Defines the username, necessary for some checks.")]
    [Alias('u')]
    [string]$username,

    [Parameter(HelpMessage = "Defines the password.")]
    [Alias('p')]
    [string]$password,

    [Parameter(HelpMessage = "Enumerate domain GPOs.")]
    [Alias('gpo')]
    [switch]$groupPolicy,

    [Parameter(HelpMessage = "Enumerates ADCS templates.")]
    [Alias('adcs')]
    [switch]$adcsTemplates,

        [Parameter(HelpMessage = "Enumerates ADCS templates fine grained with more information about the templates.")]
        [Alias('fg')]
        [switch]$fineGrained,

    [Parameter(HelpMessage = "Fetch computer objects out of active directory and scan for juicy ports (3389, 5985, 5986, 80, 443, 8080, 8443, 22, 2222, 1433).")]
    [Alias('jp')]
    [switch]$juicyPorts,

    [Parameter(HelpMessage = "Checks if the spooler service is running on servers in target OU.")]
    [Alias('pnou')]
    [switch]$printNighmareOU,

        [Parameter(HelpMessage = "Defines the ou path for pnou parameter.")]
        [Alias('sb')]
        [switch]$searchBase,

    [Parameter(HelpMessage = "Checks if the spooler service is running domain controllers.")]
    [Alias('pndc')]
    [switch]$printNighmareDC
)

function Show-Banner {
    <#
    .DESCRIPTION
        Tool Banner.
    .PARAMETER version
        Defines the tool version.
    #>

    param(
        [Parameter(HelpMessage = "Defines the tool version.")]
        [string]$version = "1.0"
    )

    Write-Host "
    
    ___  ____                     
    |  \/  (_)                    
    | .  . |_ ___  ___ ___  _ __  
    | |\/| | / __|/ __/ _ \| '_ \ 
    | |  | | \__ \ (_| (_) | | | |
    \_|  |_/_|___/\___\___/|_| |_|

    " -ForegroundColor DarkMagenta
    Write-Output "
        Author:     G0urmetD
        Version:    $version
    "
}

if($help) {
    Show-Banner
    
    Write-Host "======================================== { Description } ============================================="
    Write-Output "MisconPE is a tool to find misconfigurations, information or vulnerabilities in an Active Directory."
    Write-Host "======================================== { Parameters } =============================================="
    Write-Output "
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
    "
    exit
}

# Check if current computer is domain joined
function Test-DomainJoinStatus {
    if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
        Write-Host -ForegroundColor DarkMagenta "[INFO]" -NoNewline
        Write-Host " Current computer is part of a domain, proceed ..."
    } else {
        Write-Host -ForegroundColor RED "[ERROR]" -NoNewline
        Write-Host " Current computer is NOT part of a domain, exit ..."
        exit
    }
}

function ImportModules {
    # import of modules
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Importing the modules ..."
    $modulePath = ".\modules"
    Get-ChildItem -Path $modulePath -Filter *.psm1 | ForEach-Object { Import-Module -Name $_.FullName -Force }
}

# checks if at least one parameter was handed over
if(-not $PSBoundParameters.ContainsKey('domain')) {
    Show-Banner
    Write-Host -ForegroundColor Red "[ERROR]" -NoNewline
    Write-Host " The parameter -d/--domain is required. Use -h for further information."
    exit
} else {
    # check if domain is reachable
    $DomainJoined = Test-DomainJoinStatus

    if ($DomainJoined) {
        Write-Host -ForegroundColor Green "[INFO]" -NoNewline
        Write-Host " Computer is domain joined to $domain."
        # import modules
        ImportModules
    } elseif (!$DomainJoined) {
        Write-Host -ForegroundColor Red "[INFO]" -NoNewline
        Write-Host " Computer is NOT domain joined to $domain."
    }
}

if($all) {
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Run all checks..."

    Write-Host "========================= { Domain Information } =========================" -ForegroundColor Blue
    Write-Host "========================= { Domain Information" -ForegroundColor Blue
    Get-DomainInfo

    Write-Host "========================= { Quick Wins } =========================" -ForegroundColor Blue
    Write-Host "========================= { Kerberoastable Accounts" -ForegroundColor Blue
    Test-KerberoastableAccounts
    Write-Host ""
    Write-Host "========================= { ASREP Roastable Accounts" -ForegroundColor Blue
    Test-ASREPRoasting
    Write-Host ""
    Write-Host "========================= { DCSync" -ForegroundColor Blue
    Test-DCSync
    Write-Host ""
    Write-Host "========================= { LLMNR" -ForegroundColor Blue
    Test-LLMNR
}

if($basic) {
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Run basic misconfiguration checks..."
    Write-Host "========================= { Basic Misconfigurations } =========================" -ForegroundColor Blue
    Write-Host "========================= { Domain Information" -ForegroundColor Blue
    Get-DomainInfo

    Write-Host ""
    Write-Host "========================= { Domain Password Policy" -ForegroundColor Blue
    Test-DefaultDomainPasswordPolicy

    Write-Host ""
    Write-Host "========================= { Disabled Domain Accounts" -ForegroundColor Blue
    Test-DisabledAccounts

    Write-Host ""
    Write-Host "========================= { MachineAccountQuota" -ForegroundColor Blue
    Test-MachineAccountQuota

    Write-Host ""
    Write-Host "========================= { KRBTGT Password Last Set" -ForegroundColor Blue
    Test-KRBTGTPWLastSet

    Write-Host ""
    Write-Host "========================= { AD Administrator Information" -ForegroundColor Blue
    Test-ADAdministrator

    Write-Host ""
    Write-Host "========================= { Constrained Delegation" -ForegroundColor Blue
    Test-ConstrainedDelegation

    Write-Host ""
    Write-Host "========================= { Unconstrained Delegation" -ForegroundColor Blue
    Test-UnconstrainedDelegation

    Write-Host ""
    Write-Host "========================= { Admin Delegation" -ForegroundColor Blue
    Test-AdminDelegation

    Write-Host ""
    Write-Host "========================= { Accounts with Password Never Expires" -ForegroundColor Blue
    Test-PWNeverExpires

    Write-Host ""
    Write-Host "========================= { Domain Security Groups" -ForegroundColor Blue
    Test-SecurityGroups
}

if($kerberoast) {
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Scanning for kerberoastable accounts in the domain..."
    Write-Host "========================= { Kerberoastable Accounts" -ForegroundColor Blue
    Test-KerberoastableAccounts
}

if($asrep) {
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Scanning for asrep roastable accounts in the domain..."
    Write-Host "========================= { ASREP Roastable Accounts" -ForegroundColor Blue
    Test-ASREPRoasting
}

if($dcsync) {
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Scans for dcsync privileges..."
    Write-Host "========================= { DCSync" -ForegroundColor Blue
    Test-DCSync
}

if($llmnr) {
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Check if LLMNR is activated in the domain..."
    Write-Host "========================= { LLMNR" -ForegroundColor Blue
    Test-LLMNR
}

if($quickwins) {
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Run quickwins checks..."

    Write-Host "========================= { Quick Wins } =========================" -ForegroundColor Blue
    Write-Host "========================= { Kerberoastable Accounts" -ForegroundColor Blue
    Test-KerberoastableAccounts
    Write-Host ""
    Write-Host "========================= { ASREP Roastable Accounts" -ForegroundColor Blue
    Test-ASREPRoasting
    Write-Host ""
    Write-Host "========================= { DCSync" -ForegroundColor Blue
    Test-DCSync
    Write-Host ""
    Write-Host "========================= { LLMNR" -ForegroundColor Blue
    Test-LLMNR
}

if($info) {
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Show domain information..."
    Write-Host "========================= { Domain Information } =========================" -ForegroundColor Blue
    Write-Host "========================= { Domain Information" -ForegroundColor Blue
    Get-DomainInfo
}

if($domainACL) {
    if($username -ne $null -AND $password -ne $null) {
        Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
        Write-Host " Checks for custom domain acls on not built-in objects..."
        Write-Host "========================= { Domain ACLs" -ForegroundColor Blue
        Test-ADCredentials -Username $userName -Password $password
    }
}

if($groupPolicy) {
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Enumerate domain GPOs..."
    Write-Host "========================= { Domain Group Policies" -ForegroundColor Blue
    Test-GPOs
}

if($adcsTemplates) {
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Enumerate ADCS templates..."
    Write-Host "========================= { ADCS templates" -ForegroundColor Blue
    if(-not($FineGrained)) {
        Write-Host -ForegroundColor Cyan "[INFO]" -NoNewline
        Write-Host " Fetching ADCS templates ..."
        Get-ADCSTemplate | Format-Table
    } else {
        Write-Host -ForegroundColor Cyan "[INFO]" -NoNewline
        Write-Host " Fetching fine grained ADCS templates ..."
        Get-ADCSTemplate
    }
}

if($juicyPorts) {
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Let's find some juicy ports..."
    Write-Host "========================= { Juicy Ports" -ForegroundColor Blue
    Test-JuicyPorts
}

if($pnou) {
    if(-not ($searchbase -or $sb)) {
        Write-Host -ForegroundColor Red "[ERROR]" -NoNewline
        Write-Host " The -sb/-searchbase parameter is required when using -pnou. Use -h for further information. ..."
    } else {
        Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
        Write-Host " Looking for running spooler service..."
        Write-Host "========================= { PrintNightmare" -ForegroundColor Blue
        Test-PrintNightmareOU
    }
}

if ($pndc) {
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Looking for running spooler service on domain controllers..."
    Write-Host "========================= { PrintNightmare" -ForegroundColor Blue

    if (-not $username -or -not $password) {
        Write-Host -ForegroundColor RED "[ERROR]" -NoNewline
        Write-Host " Username and password are required."
        exit
    }

    $PrintNightmareDC = Test-PrintNightmareDC -Username $username -Password (ConvertFrom-SecureString -SecureString $password -AsPlainText)
    $PrintNightmareDC | Format-Table

    if ($PrintNightmareDC.State -eq "Running") {
        Write-Host -ForegroundColor Red "[VULNERABLE]" -NoNewline
        Write-Host " Your domain controller is vulnerable, spooler service is running ..."
    }
}
