<#
.DESCRIPTION
    The Miscon tool can identify basic misconfigurations and quick wins from an IT security perspective.
.PARAMETER help
    [optional] Shows the help for young padawans.
.PARAMETER domain
    [required] Defines the Active Directory domain.
.PARAMETER info
    [optional] Starts Basic Domain Information Enumeration.
.PARAMETER basic
    [optional] Starts searching for basic misconfigurations.
.PARAMETER quick
    [optional] Starts searching for quickwins like AS-REP Roasting/Kerberoastable Accounts/LLMNR.
.PARAMETER pndc
    [optional] Checks if the spooler service is running on the domain controllers.
.PARAMETER pnou
    [optional] Checks if the spooler service is running on servers in target OU.
.PARAMETER searchbase
    [optional] Defines ou path for pnou parameter.
.PARAMETER dacl
    [optional] Checks for custom domain acls.
.PARAMETER username
    [optional] Defines the Active Directory username.
.PARAMETER password
    [optional] Defines the Active Directory password.
.PARAMETER GPO
    [optional] Starts GPO enumeration.
.PARAMETER domainGPOs
    [optional] GPO array for GPO enumeration.
.PARAMETER ADCSTemplates
    [optional] Enumerates ADCS templates.
.PARAMETER FineGrained
    [optional] Enumerates ADCS templates fine grained with more information about the templates.
#>

param(
    [Parameter(HelpMessage = "Shows the help for young padawans.")]    
    [switch]$help,

    [Parameter(HelpMessage = "Defines the Active Directory domain.")]
    [Alias('d')]
    [string]$domain,

    [Parameter(HelpMessage = "Starts Basic Domain Information Enumeration.")]
    [Alias('i')]
    [switch]$info,

    [Parameter(HelpMessage = "Starts searching for basic misconfigurations.")]
    [Alias('b')]
    [switch]$basic,

    [Parameter(HelpMessage = "Starts searching for quickwins like AS-REP Roasting/Kerberoastable Accounts/LLMNR.")]
    [Alias('q')]
    [switch]$quick,

    [Parameter(HelpMessage = "Checks if the spooler service is running on the domain controllers.")]
    [switch]$pndc,

    [Parameter(HelpMessage = "Checks if the spooler service is running on servers in target OU.")]
    [switch]$pnou,

    [Parameter(HelpMessage = "Defines ou path for pnou parameter.")]
    [Alias('sb')]
    [switch]$searchbase,

    [Parameter(HelpMessage = "Checks for custom domain acls on not built-in objects.")]
    [switch]$dacl,

    [Parameter(HelpMessage = "Defines the Active Directory username.")]
    [Alias('u')]
    [string]$username,

    [Parameter(HelpMessage = "Defines the Active Directory password.")]
    [Alias('p')]
    [string]$password,

    [Parameter(HelpMessage = "Starts GPO enumeration.")]
    [Alias('g')]
    [switch]$GPO,

    [Parameter(HelpMessage = "GPO array.")]
    [string[]]$domainGPOs,

    [Parameter(HelpMessage = "Enumerates ADCS templates.")]
    [Alias('adcs')]
    [switch]$ADCSTemplates,

    [Parameter(HelpMessage = "Enumerates ADCS templates fine grained with more information about the templates.")]
    [Alias('fg')]
    [switch]$FineGrained
)

# import of modules
Import-Module ".\modules\banner.psm1" -Force
Import-Module ".\modules\domainInfo.psm1" -Force
Import-Module ".\modules\basic-misconfigurations.psm1" -Force
Import-Module ".\modules\quickwins.psm1" -Force
Import-Module ".\modules\printNightmare-DC.psm1" -Force
Import-Module ".\modules\printNightmare-OU.psm1" -Force
Import-Module ".\modules\domainacls.psm1" -Force
Import-Module ".\modules\gpo.psm1" -Force
Import-Module ".\modules\adcs-templates.psm1" -Force

if($help) {
    Show-Banner
    Write-Output "[INFO] Here is some help ..."
    Write-Output "Usage: Miscon.ps1 -d <domain> [-u/-username <username>] [-p/-password <password>] [-h] [-i/-info] [-b/-basic] [-q/-quick] 
                                    [-pndc] [-pnou -sb <searchbase>] [-dacl -u <username> -p <password>] [-g/-gpo] [-adcs/-ADCSTemplates -fg/-FineGrained]"
    Write-Output ""
    Write-Output "Parameters:"
    Write-Output "------------------------------------------------------------------------------------------------------------------"
    Write-Output "[Required]    -d, -domain              Defines the Active Directory domain."
    Write-Output "[Optional]    -i, -info                Starts Basic Domain Information Enumeration."
    Write-Output "[Optional]    -b, -basic               Starts searching for basic misconfigurations."
    Write-Output "[Optional]    -q, -quick               Starts searching for quickwins like AS-REP Roasting/Kerberoastable Accounts/LLMNR."
    Write-Output "[Optional]    -pndc, -pndc             Checks if the spooler service is running on the domain controllers."
    Write-Output "[Optional]    -pnou, -pnou             Checks if the spooler service is running on servers in target OU."
    Write-Output "[Optional]        -sb, -searchbase         Defines ou path for pnou parameter."
    Write-Output "[Optional]    -dacl, -dacl             Checks for custom domain acls on not built-in objects."
    Write-Output "[Optional]        -u, -username            Defines the Active Directory username."
    Write-Output "[Optional]        -p, -password            Defines the Active Directory user password."
    Write-Output "[Optional]    -g, -gpo                 Enumerate domain GPOs."
    Write-Output "[Optional]    -adcs, -ADCSTemplates    Enumerates ADCS templates."
    Write-Output "[Optional]        -fg, -FineGrained        Enumerates ADCS templates fine grained with more information about the templates."
    exit
}

# Check if current computer is domain joined
function Test-DomainJoinStatus {
    if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
        return $true
    } else {
        return $false
    }
}

# checks if at least one parameter was handed over
if(-not $PSBoundParameters.ContainsKey('domain')) {
    Show-Banner
    Write-Host "[ERROR] The parameter -d/--domain is required. Use -h for further information."
    exit
} else {
    # check if domain is reachable
    $DomainJoined = Test-DomainJoinStatus

    if ($DomainJoined) {
        Write-Host -ForegroundColor Green "[INFO]" -NoNewline
        Write-Host " Computer is domain joined to $domain."
    } elseif (!$DomainJoined) {
        Write-Host -ForegroundColor Red "[INFO]" -NoNewline
        Write-Host " Computer is NOT domain joined to $domain."
        $answer = Read-Host "You wanna anyway start your enumeration? (Y/N)"
        if(-not ($answer -eq "Y")) {
            Write-Host -ForegroundColor Red "[INFO]" -NoNewline
            Write-Host " Exit out, see you again."
            Exit
        }
    }
}

Show-Banner

if($i -or $info) {
    # call domainInfo function from domainInfo module
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Fetching Domain information ..."
    $domainInfo = Get-DomainInfo
    # show DomainInfo Output
    Write-Output "Domain Name:                      $($domainInfo.DomainName)"
    Write-Output "Domain Controller:                $($domainInfo.DomainController)"
    Write-Output "Domain Functional Level:          $($domainInfo.DomainFunctionalLevel)"
    Write-Output "Forest Functional Level:          $($domainInfo.ForestFunctionalLevel)"
    Write-Output "Domain Controllers:               $($domainInfo.DomainControllers -join ', ')"
    Write-Output "Sites:                            $($domainInfo.Sites -join ', ')"
    Write-Output "Number of Sites:                  $($domainInfo.SitesCount)"
    Write-Output "Domain Administrators:            $($domainInfo.DomainAdmins -join ', ')"
    Write-Output "Number of Domain Administrators:  $($domainInfo.DomainAdminsCount)"
    Write-Output "Number of Users:                  $($domainInfo.UsersCount)"
    Write-Output "Number of Computers:              $($domainInfo.ComputersCount)"
    Write-Output ""
}

if($b -or $basic) {
    # call Test-DefaultDomainPasswordPolicy function from basic-misconfigurations module
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Searching for basic misconfigurations ..."
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Testing default domain policy ..."
    $result = Test-DefaultDomainPasswordPolicy
    # show Test-DefaultDomainPasswordPolicy Output
    if($result.ComplexityEnabled -eq $False) {
        Write-Host "ComplexityEnabled:                $($result.ComplexityEnabled)" -ForegroundColor Red
    } else {
        Write-Output "ComplexityEnabled:                $($result.ComplexityEnabled)"
    }
    if($result.MinPasswordLength -lt 10) {
        Write-Host "MinPasswordLength:                $($result.MinPasswordLength)" -ForegroundColor Red
    } else {
        Write-Output "MinPasswordLength:              $($result.MinPasswordLength)"
    }
    Write-Output "MaxPasswordLength:                $($result.MaxPasswordLength)"
    Write-Output "MinPasswordAge:                   $($result.MinPasswordAge)"
    Write-Output "MaxPasswordAge:                   $($result.MaxPasswordAge)"
    if($result.PasswordHistoryCount -lt 15) {
        Write-Host "PasswordHistoryCount:             $($result.PasswordHistoryCount)" -ForegroundColor Red
    } else {
        Write-Output "PasswordHistoryCount:             $($result.PasswordHistoryCount)"
    }
    Write-Output "Lockout Treshold:                 $($result.LockoutTreshold)"
    Write-Output "Lockout Observation window:       $($result.LockoutObservationWindow)"
    Write-Output "Lockout duration:                 $($result.LockoutDuration)"
    Write-Output ""

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Searching for disabled accounts ..."
    $disabledAccounts = Test-DisabledAccounts
    $disabledAccounts
    Write-Output ""

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Searching for machine account Quota = ms-DS-MachineAccountQuota ..."
    $machineAccountQuota = Test-MachineAccountQuota
    Write-Output "DistinguishedName:                $($machineAccountQuota.DistinguishedName)"
    Write-Output "ms-DS-MachineAccountQuota:        $($machineAccountQuota.'ms-DS-MachineAccountQuota')"
    Write-Output "Name:                             $($machineAccountQuota.Name)"
    Write-Output "ObjectClass:                      $($machineAccountQuota.ObjectClass)"
    Write-Output "ObjectGUID:                       $($machineAccountQuota.ObjectGUID)"
    Write-Output ""

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Check when krbtgt password last set ..."
    $krbtgtpwlastSet = Test-KRBTGTPWLastSet
    $krbtgtpwlastSet
    Write-Output ""

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Check when AD administrator password last set ..."
    $ADAdministratorPWLastSet = Test-ADAdministrator
    $ADAdministratorPWLastSet
    Write-Output ""

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Search for users with constrained delegation."
    $testconstrainedDelegation = Test-ConstrainedDelegation
    if(-not ($testconstrainedDelegation)) {
        Write-Host -ForegroundColor Red "[SAD]" -NoNewline
        Write-Host " Could not found users with constrained delegation."
    } else {
        Write-Host -ForegroundColor Green "[FOUND]" -NoNewline
        Write-Host " Search process was successful."
        Write-Host -ForegroundColor Cyan "[NOTE]" -NoNewline
        Write-Host " A user or a service can pass on the Kerberos ticket of a client to another service without any restrictions."
        $testconstrainedDelegation
    }
    Write-Output ""

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Search for users with unconstrained delegation."
    $testunconstrainedDelegation = Test-UnconstrainedDelegation
    if(-not ($testunconstrainedDelegation)) {
        Write-Host -ForegroundColor Red "[SAD]" -NoNewline
        Write-Host " Could not found users with unconstrained delegation."
    } else {
        Write-Host -ForegroundColor Green "[FOUND]" -NoNewline
        Write-Host " Search process was successful."
        Write-Host -ForegroundColor Cyan "[NOTE]" -NoNewline
        Write-Host " Delegation is restricted to certain services or resources to which a user or service may have access.."
        $testunconstrainedDelegation
    }
    Write-Output ""

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Checking if users have admincount greater than 0 and Kerberos Delegation activated ..."
    $admincount = Test-AdminDelegation
    $admincount | Format-Table
    Write-Output ""

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Never changing a bad password is bad for the whole Domain, especially Service Accounts. ..."
    $pwNeverExpires = Test-PWNeverExpires
    $pwNeverExpires | Format-Table
    Write-Output ""

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Checking Security group members ..."
    Write-Host -ForegroundColor MAGENTA "[INFO]" -NoNewline
    Write-Host " Some groups should be empty ..."
    $securityGroups = Test-SecurityGroups
    $securityGroups | Format-Table
    Write-Output ""
}

if($q -or $quick) {
    Write-Host -ForegroundColor MAGENTA "[INFO]" -NoNewline
    Write-Host " Checking for AS-REP Roasting ..."
    $ASREPROASTING = Test-ASREPRoasting
    $ASREPROASTING | Format-Table
    Write-Output ""

    Write-Host -ForegroundColor MAGENTA "[INFO]" -NoNewline
    Write-Host " Checking for AS-REP Roasting ..."
    $kerberoastableAccounts = Test-KerberoastableAccounts
    $kerberoastableAccounts | Format-Table
    Write-Output ""

    Write-Host -ForegroundColor MAGENTA "[INFO]" -NoNewline
    Write-Host " Checking for LLMNR ..."
    $llmnrCheck = Test-LLMNR
    $llmnrCheck | Format-Table
    Write-Output ""

    Write-Host -ForegroundColor MAGENTA "[INFO]" -NoNewline
    Write-Host " Checking for DCSync rights ..."
    $dcsyncCheck = Test-DCSync
    $dcsyncCheck
    Write-Output ""
}

if($pndc) {
    Write-Host -ForegroundColor Cyan "[INFO]" -NoNewline
    Write-Host " Checks if the spooler service is running on the domain controllers ..."
    $PrintNightmareDC = Test-PrintNightmareDC
    $PrintNightmareDC | Format-Table

    if($PrintNightmareDC.State -eq "Running") {
        Write-Host -ForegroundColor Red "[VULNERABLE]" -NoNewline
        Write-Host " Your domain controller is vulnerable, spooler service is running ..."
    }
    Write-Output ""
}

if($pnou) {
    if(-not ($searchbase -or $sb)) {
        Write-Host -ForegroundColor Red "[ERROR]" -NoNewline
        Write-Host " The -sb/-searchbase parameter is required when using -pnou. Use -h for further information. ..."
    } else {
        Write-Host -ForegroundColor Cyan "[INFO]" -NoNewline
        Write-Host " Checks if the spooler service is running on servers in target OU ..."
        Test-PrintNightmareOU | Format-Table
        Write-Output ""
    }
}

if($dacl) {
    # test ad credentials & if valid -> run custom dacl check
    Test-ADCredentials -Username $userName -Password $password
}

if($gpo) {
    # enumerate domain GPO's
    Test-GPOs
}

if($ADCSTemplates) {
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
