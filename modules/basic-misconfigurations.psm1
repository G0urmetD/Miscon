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