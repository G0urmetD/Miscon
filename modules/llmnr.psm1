function Test-LLMNR {
    $checkLLMNR = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -name EnableMulticast -ErrorAction SilentlyContinue
    
    if($checkLLMNR.EnableMulticast -eq "0")
    {
        Write-Host "[+] LLMNR is deactivated." -ForegroundColor Green
    } else {
        Write-Host "[!] LLMNR is enabled. Should be deactivated." -ForegroundColor Red
    }
}