function Test-PrintNightmareDC {
    $Domains = (Get-ADForest).Domains | ForEach-Object {Get-ADDomain -Server $_} | Select-Object Name,ReplicaDirectoryServers,ReadOnlyReplicaDirectoryServers

    $DCS = @()
    ForEach($Domain in $Domains){
        ForEach ($DomainController in $Domain.ReplicaDirectoryServers){
            try{
                $result = Get-Service -ComputerName $DomainController -Name Spooler -ErrorAction Stop | Select-Object Status,Name
            } catch{

                Write-Host "Error checking $($DomainController)" -ForegroundColor Red

            }
            $Object = New-Object PSObject -Property @{
                DomainController = $DomainController
                Serivce = $result.Name
                State = $result.Status
            }
            $DCS += $Object
        }
        ForEach ($DomainController in $Domain.ReadOnlyReplicaDirectoryServers){
            try{
                $result = Get-Service -ComputerName $DomainController -Name Spooler -ErrorAction Stop | Select-Object Status,Name
            } catch{

                Write-Host "Error checking $($DomainController)" -ForegroundColor Red

            }
            $Object = New-Object PSObject -Property @{
                DomainController = $DomainController
                Serivce = $result.Name
                State = $result.Status
            }
            $DCS += $Object
        }
    }
    $DCs
}
