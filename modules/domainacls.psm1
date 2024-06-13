function Test-DomainACLsSID {
    param (
        [Parameter(HelpMessage = "The username to use for accessing Active Directory.")]
        [string]$Username,

        [Parameter(HelpMessage = "The password to use for accessing Active Directory.")]
        [string]$Password
    )

    # Define the SID for the built-in administrator group
    $builtinAdminsSID = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

    # Create an empty list to save the objects found
    $objectsWithCustomACLs = @()

    # Searching the objects in the domain
    Get-ADObject -Filter * -Properties * -Credential (New-Object System.Management.Automation.PSCredential($Username, (ConvertTo-SecureString $Password -AsPlainText -Force))) | ForEach-Object {
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

function Test-ADCredentials {
    param (
        [Parameter(HelpMessage = "The username to test.")]
        [string]$Username,

        [Parameter(HelpMessage = "The password to test.")]
        [string]$Password
    )

    try {
        # try to create a connection to active directory
        $null = Get-ADUser -Filter * -Credential (New-Object System.Management.Automation.PSCredential($Username, (ConvertTo-SecureString $Password -AsPlainText -Force))) -ErrorAction Stop
        Write-Host -ForegroundColor Green "[VALID]" -NoNewline
        Write-Host " Credentials are valid ..."

        Write-Host -ForegroundColor Cyan "[INFO]" -NoNewline
        Write-Host " Checks for custom domain acls on not built-in objects ..."
        Test-DomainACLsSID -Username $username -Password $password
        Write-Output ""

    }
    catch {
        Write-Host -ForegroundColor Red "[ERROR]" -NoNewline
        Write-Host " Failed to authenticate with the provided credentials: $($_.Exception.Message)"
    }
}
