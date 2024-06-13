function Test-JuicyPorts {
    <#
    .DESCRIPTION
        Fetching Active Directory computer objects and scan hostnames for juicy ports like: 3389 (RDP), 5985/5986 (WinRM)
    #>
    param(
        [Parameter(HelpMessage = "Shows the help for young padawans.")]    
        [string[]]$ports = @(3389, 5985, 5986, 80, 443, 8443, 22, 2222, 1433, 1801)
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

        if(1801 -in $juicyPorts) {
            $hint += "[WARN] This computer is vulnerable to CVE-2024-30080."
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