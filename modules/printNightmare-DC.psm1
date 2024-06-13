function Test-PrintNightmareDC {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    # Konvertiere Passwort in ein SecureString-Objekt
    $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force

    # Erstelle ein PSCredential-Objekt mit dem Benutzernamen und dem SecureString-Passwort
    $Credential = New-Object System.Management.Automation.PSCredential ($Username, $SecurePassword)

    $Domains = (Get-ADForest).Domains | ForEach-Object {Get-ADDomain -Server $_} | Select-Object Name, ReplicaDirectoryServers, ReadOnlyReplicaDirectoryServers

    $DCS = @()
    ForEach ($Domain in $Domains) {
        ForEach ($DomainController in $Domain.ReplicaDirectoryServers) {
            try {
                $result = Get-Service -ComputerName $DomainController -Name Spooler -Credential $Credential -ErrorAction Stop | Select-Object Status, Name
            } catch {
                Write-Host "Error checking $($DomainController)" -ForegroundColor Red
                continue
            }
            $Object = New-Object PSObject -Property @{
                DomainController = $DomainController
                Service = $result.Name
                State = $result.Status
            }
            $DCS += $Object
        }
        ForEach ($DomainController in $Domain.ReadOnlyReplicaDirectoryServers) {
            try {
                $result = Get-Service -ComputerName $DomainController -Name Spooler -Credential $Credential -ErrorAction Stop | Select-Object Status, Name
            } catch {
                Write-Host "Error checking $($DomainController)" -ForegroundColor Red
                continue
            }
            $Object = New-Object PSObject -Property @{
                DomainController = $DomainController
                Service = $result.Name
                State = $result.Status
            }
            $DCS += $Object
        }
    }
    $DCS
}