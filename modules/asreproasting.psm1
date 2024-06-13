function Test-ASREPRoasting {
    $asREPRoasting = Get-ADUser -Filter * -Properties DoesNotRequirePreAuth | Where-Object DoesNotRequirePreAuth -eq $true | Select-Object Name,SamAccountName,Enabled,DoesNotRequirePreAuth

    if($asREPRoasting -ne $null) {
        $asREPRoasting | Format-Table
    }
}