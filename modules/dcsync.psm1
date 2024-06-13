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