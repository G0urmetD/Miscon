function Test-DefaultDomainPasswordPolicy {
    $defaultdomainPWPolicy = Get-ADDefaultDomainPasswordPolicy

    $result = @{
        ComplexityEnabled = $defaultdomainPWPolicy.ComplexityEnabled
        MinPasswordLength = $defaultdomainPWPolicy.MinPasswordLength
        MaxPasswordLength = $defaultdomainPWPolicy.MaxPasswordLength
        MinPasswordAge = $defaultdomainPWPolicy.MinPasswordAge
        MaxPasswordAge = $defaultdomainPWPolicy.MaxPasswordAge
        PasswordHistoryCount = $defaultdomainPWPolicy.PasswordHistoryCount
        LockoutTreshold = $defaultdomainPWPolicy.LockoutTreshold
        LockoutObservationWindow = $defaultdomainPWPolicy.LockoutObservationWindow
        LockoutDuration = $defaultdomainPWPolicy.LockoutDuration
    }

    return $result
}

function Test-DisabledAccounts {
    $disabeldAccounts = Get-ADUser -Filter {Enabled -eq $False} -Properties Name

    if($disabeldAccounts) {
        $disabeldAccounts | Select-Object Name,SamAccountName,Enabled,DistinguishedName | Format-Table
    } else {
        Write-Host -ForegroundColor RED "[INFO]" -NoNewline
        Write-Host " No disabled accounts detected ..."
    }
}

function Test-MachineAccountQuota {
    $MachineAccountQuota = Get-ADObject ((Get-ADDomain).DistinguishedName) -Properties ms-DS-MachineAccountQuota

    $results = @{
        DistinguishedName = $MachineAccountQuota.DistinguishedName
        msDSMachineAccountQuota = $MachineAccountQuota.'ms-DS-MachineAccountQuota'
        Name = $MachineAccountQuota.Name
        ObjectClass = $MachineAccountQuota.ObjectClass
        ObjectGUID = $MachineAccountQuota.ObjectGUID
    }

    return $results
}

function Test-KRBTGTPWLastSet {
    $krbtgtPWlastSet = Get-ADUser "krbtgt" -Property Created,PasswordLastSet | Select-Object Created,PasswordLastSet

    if($krbtgtPWlastSet) {
        $krbtgtPWlastSet | Format-Table
    } else {
        Write-Host -ForegroundColor RED "[INFO]" -NoNewline
        Write-Host " Something went wrong, Could not fetch krbtgt account information ..."
    }
}

function Test-ADAdministrator {
    $adadminPasswordLastSet = Get-ADUser -Filter * -Properties * | Select-Object SID,SamAccountName,Enabled,UserPrincipalName,PasswordLastSet | Where-Object -Property SID -like "*-500" | Out-Host

    if($adadminPasswordLastSet) {
        $adadminPasswordLastSet | Format-Table
    }
}

function Test-ConstrainedDelegation {
    $users = Get-ADUser -LdapFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*))"

    foreach ($user in $users) {

        Write-output
        write-output($user.sAMAccountName)
        Get-ADUser $user -Properties msDS-AllowedToDelegateTo,Displayname | Select-Object Displayname -ExpandProperty msDS-AllowedToDelegateTo | Format-Table
        write-output("")
    }
}

function Test-UnconstrainedDelegation {
    $users = Get-ADUser -Filter "msDS-AllowedToDelegateTo -like '*'" -Properties msDS-AllowedToDelegateTo,userAccountControl | Where-Object { $_.Enabled -eq $true }

    foreach ($user in $users) {
        Write-output("")
        write-output($user.sAMAccountName)
        Get-ADUser $user -Properties msDS-AllowedToDelegateTo,DisplayName | Select-Object DisplayName -ExpandProperty msDS-AllowedToDelegateTo | Format-List
        write-output("")
    }
}

function Test-AdminDelegation {
    $admincountKerberosDelegation = Get-ADUser -Filter {(AdminCount -eq 1) -and (AccountNotDelegated -eq $false)} | Format-Table sAMAccountName,DistinguishedName,AccountNotDelegated

    if($admincountKerberosDelegation) {
        $admincountKerberosDelegation | Format-Table
    }
}

function Test-PWNeverExpires {
    $pwNeverExpires = Get-ADUser -filter * -properties Name, PasswordNeverExpires | Where-Object { $_.passwordNeverExpires -eq "true" } |  Select-Object DistinguishedName,Name,Enabled,PasswordNeverExpires | Format-Table

    if($pwNeverExpires) {
        $pwNeverExpires | Format-Table
    }
}

function Test-SecurityGroups {
    $OSInfo = Get-WmiObject -Class Win32_OperatingSystem
    $languagepack = $OSInfo.MUILanguages

    # Get group members of DNSAdmins
    Write-Output "[INFO] Group Members of DNSAdmins"
    if($languagepack -eq "de-DE") {
        Get-ADGroupMember 'DnsAdmins' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } elseif ($languagepack -eq "en-EN") {
        Get-ADGroupMember 'DNSAdmins' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } else {
        Write-Host -ForegroundColor Red "[x]" -NoNewline
        Write-Host " No supported langugage detected."   
    }

    # Get group members of Schema-Admins
    Write-Output "[INFO] Group Members of Schema-Admins"
    if($languagepack -eq "de-DE") {
        Get-ADGroupMember 'Schema-Admins' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } elseif ($languagepack -eq "en-EN") {
        Get-ADGroupMember 'Schema Admins' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } else {
        Write-Host -ForegroundColor Red "[x]" -NoNewline
        Write-Host " No supported langugage detected."   
    }

    # Get group members of Enterprise Admins
    Write-Output "[INFO] Group Members of Enterprise-Admins/Organisations-Admins"
    if($languagepack -eq "de-DE") {
        Get-ADGroupMember 'Organisations-Admins' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } elseif ($languagepack -eq "en-EN") {
        Get-ADGroupMember 'Enterprise Admins' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } else {
        Write-Host -ForegroundColor Red "[x]" -NoNewline
        Write-Host " No supported langugage detected."   
    }

    # Get group members of Enterprise Admins
    Write-Output "[INFO] Group Members of Administrators"
    if($languagepack -eq "de-DE") {
        Get-ADGroupMember 'Administratoren' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } elseif ($languagepack -eq "en-EN") {
        Get-ADGroupMember 'Administrators' | Select-Object Name,SamAccountName,distinguishedName,SID | Format-Table
    } else {
        Write-Host -ForegroundColor Red "[x]" -NoNewline
        Write-Host " No supported langugage detected."   
    }
}