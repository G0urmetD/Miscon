function Test-JuicyPorts {
    <#
    .DESCRIPTION
        Fetching Active Directory computer objects and scan hostnames for juicy ports like: 3389 (RDP), 5985/5986 (WinRM)
    #>
    param(
        [Parameter(HelpMessage = "Shows the help for young padawans.")]    
        [string[]]$ports = @(3389, 5985, 5986)
    )
    # fetching computer objects from Active Directory
    $computers = Get-ADComputer -Filter *

    $results = @()

    foreach ($computer in $computers) {
        $computerName = $computer.Name
        $ipAddress = [System.Net.Dns]::GetHostAddresses($computerName) | Where-Object { $_.AddressFamily -eq "InterNetwork" } | Select-Object -ExpandProperty IPAddressToString

        $openPorts = @()

        foreach ($port in $ports) {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $result = $tcpClient.BeginConnect($computerName, $port, $null, $null)
            $result.AsyncWaitHandle.WaitOne(1000, $false)

            if ($tcpClient.Connected) {
                $openPorts += $port
                $tcpClient.Close()
            }
        }

        $resultObject = [PSCustomObject]@{
            Hostname = $computerName
            'IP-Adresse' = $ipAddress
            'Offene Ports' = $openPorts -join ', '
        }

        $results += $resultObject
    }

    $results | Format-Table -AutoSize
}
