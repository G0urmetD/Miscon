# NOTE: NOT TESTED - Only one function will made it into main
function Test-DomainACLs {
    <#
    .DESCRIPTION
        Search for objects with non-built-in ACLs with modification rights
    #>
    # Create an empty list to save the objects found
    $objectsWithCustomACLs = @()

    # Searching the objects in the domain
    Get-ADObject -Filter * -Properties * | ForEach-Object {
        $object = $_
        
        # Check whether the object has an ACL
        if ($object.ACL) {
            # Running through the ACL entries of the object
            foreach ($aclEntry in $object.ACL) {
                # Check whether the ACL entry grants modification rights and whether the underlying object is not installed
                if (($aclEntry.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) -and 
                    ($aclEntry.IdentityReference -notlike "BUILTIN\*")) {
                    # Adding the object to the list
                    $objectsWithCustomACLs += $object
                    break
                }
            }
        }
    }

    # Output of the objects found
    $objectsWithCustomACLs
}

function Test-DomainACLsSID {
    <#
    .DESCRIPTION
        Search for objects with non-built-in ACLs with modification rights
    #>

    # Define the SID for the built-in administrator group
    $builtinAdminsSID = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

    # Create an empty list to save the objects found
    $objectsWithCustomACLs = @()

    # Searching the objects in the domain
    Get-ADObject -Filter * -Properties * | ForEach-Object {
        $object = $_
        
        # Check whether the object has an ACL
        if ($object.ACL) {
            # Running through the ACL entries of the object
            foreach ($aclEntry in $object.ACL) {
                # Check whether the ACL entry grants modification rights and whether the underlying object is not installed
                if (($aclEntry.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) -and 
                    ($aclEntry.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -ne $builtinAdminsSID.Value)) {
                    # Adding the object to the list
                    $objectsWithCustomACLs += $object
                    break
                }
            }
        }
    }

    # Output of the objects found
    $objectsWithCustomACLs
}
