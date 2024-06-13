function Test-KerberoastableAccounts {
    $kerberoastableAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
    
    if($kerberoastableAccounts -ne $null) {
        $kerberoastableAccounts | Format-Table
    }
}