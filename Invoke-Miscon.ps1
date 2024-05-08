param(
    [Parameter(HelpMessage = "Show Help for young padawans.")]    
    [switch]$help,

    [Parameter(HelpMessage = "Defines the Active Directory domain.")]
    [string]$domain,

    [Parameter(HelpMessage = "Defines the Active Directory username.")]
    [string]$username,

    [Parameter(HelpMessage = "Defines the Active Directory password.")]
    [string]$password,

    [Parameter(HelpMessage = "Starts Basic Domain Information Enumeration")]
    [switch]$info,

    [Parameter(HelpMessage = "Starts searching for basic misconfigurations.")]
    [switch]$basic
)

# import of modules
Import-Module ".\modules\banner.psm1" -Force
Import-Module ".\modules\domainInfo.psm1" -Force
Import-Module ".\modules\basic-misconfigurations.psm1" -Force

if($help) {
    Show-Banner
    Write-Output "[INFO] Here is some help ..."
    Write-Output "Usage: Miscon.ps1 -d <domain> [-u <username>] [-p <password>] [-h]"
    Write-Output "Parameters:"
    Write-Output "-d, -domain              Defines the Active Directory domain. [required]"
    Write-Output "-u, -username            Defines the Active Directory username. [optional]"
    Write-Output "-p, -password            Defines the Active Directory user password. [optional]"
    Write-Output "-i, -info                Starts Basic Domain Information Enumeration [Optional]"
    Write-Output "-b, -basic               Starts searching for basic misconfigurations [Optional]"
    exit
}

# checks if at least one parameter was handed over
if(-not $PSBoundParameters.ContainsKey('domain')) {
    Show-Banner
    Write-Host "[ERROR] The parameter -d/--domain is required. Use -h for further information."
    exit
}

Show-Banner

if($info) {
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

if($basic) {
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
}
