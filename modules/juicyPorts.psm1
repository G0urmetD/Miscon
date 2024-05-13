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

    Write-Host -ForegroundColor Yellow "[INFO]" -NoNewline
    Write-Host " Fetching computer objects out of the domain."
    Write-Host -ForegroundColor Yellow "[INFO]" -NoNewline
    Write-Host " Scan for juicy ports."

    foreach ($computer in $computers) {
        $computerName = $computer.Name
        $ipAddress = [System.Net.Dns]::GetHostAddresses($computerName) | Where-Object { $_.AddressFamily -eq "InterNetwork" } | Select-Object -ExpandProperty IPAddressToString

        $openPorts = @()

        foreach ($port in $ports) {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $result = $tcpClient.BeginConnect($computerName, $port, $null, $null)
            $result.AsyncWaitHandle.WaitOne(1000, $false) | Out-Null

            if ($tcpClient.Connected) {
                $openPorts += $port
                $tcpClient.Close()
            }

            $tcpClient.Dispose()
        }

        $hint = @()

        if(5985 -in $openPorts) {
            $hint += "[INFO] WinRM should be used with HTTPS/5986. Happy evil-winrm ;)"
        }
        
        if(3389 -in $openPorts) {
            $hint += "[INFO] RDP on clients should be disabled. Happy connection ;)"
        }

        $resultObject = [PSCustomObject]@{
            Hostname = $computerName
            'IP-Address' = $ipAddress
            'juicy Ports' = $openPorts -join ', '
            Hint = $hint -join ', '
        }

        $results += $resultObject
    }

    $results | Format-Table -AutoSize
}
