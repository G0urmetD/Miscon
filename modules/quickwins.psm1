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
