function Test-ASREPRoasting {
    $asREPRoasting = Get-ADUser -Filter * -Properties DoesNotRequirePreAuth | Where-Object DoesNotRequirePreAuth -eq $true | Select-Object Name,SamAccountName,Enabled,DoesNotRequirePreAuth

    if($asREPRoasting -ne $null) {
        $asREPRoasting | Format-Table
    }
}

function Test-KerberoastableAccounts {
    $kerberoastableAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
    
    if($kerberoastableAccounts -ne $null) {
        $kerberoastableAccounts | Format-Table
    }
}

function Test-LLMNR {
    $checkLLMNR = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -name EnableMulticast -ErrorAction SilentlyContinue
    
    if($checkLLMNR.EnableMulticast -eq "0")
    {
        Write-Host "[+] LLMNR is deactivated." -ForegroundColor Green
    } else {
        Write-Host "[!] LLMNR is enabled. Should be deactivated." -ForegroundColor Red
    }
}

function Test-DCSync {
    $domainInfo = Get-ADDomain
    $DistinguishedName = $domainInfo.DistinguishedName

    $acl = Get-Acl "AD:\$DistinguishedName"

    foreach ($ace in $acl.Access) {
        if ($ace.ObjectType -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or
            $ace.ActiveDirectoryRights -match 'GenericAll' -or
            $ace.ActiveDirectoryRights -match 'WriteDacl') {
            Write-Output "Berechtigung gefunden:"
            Write-Output $ace
        }
    }
}
