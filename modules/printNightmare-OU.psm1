function Test-PrintNightmareOU {
    
    param(
        [Parameter(Mandatory = $false, HelpMessage = "Defines target OU.")]
        [string]$searchbase
    )

    if($OU) {
        $machines = Get-ADComputer -SearchBase $searchbase -Filter * | Select-Object Name

        $DCS = @()
        ForEach ($machine in $machines){
                try{
                    $result = Get-Service -ComputerName $machine.name -Name Spooler -ErrorAction stop | Select-Object Status,Name
                }catch{

                    Write-Host "Error checking $($machine)" -ForegroundColor Red

                }
                $Object = New-Object PSObject -Property @{
                    Machine = $machine.Name
                    Serivce = $result.Name
                    State = $result.Status
                }
                $DCS += $Object
            }
        $dcs
    }   
}
