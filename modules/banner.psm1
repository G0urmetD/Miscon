function Show-Banner {
    <#
    .DESCRIPTION
        Tool Banner.
    .PARAMETER version
        Defines the version.
    #>

    param(
        [string]$version = "1.8.2"
    )

    Write-Host "
    ___  ____                     
    |  \/  (_)                    
    | .  . |_ ___  ___ ___  _ __  
    | |\/| | / __|/ __/ _ \| '_ \ 
    | |  | | \__ \ (_| (_) | | | |
    \_|  |_/_|___/\___\___/|_| |_|
    
    " -ForegroundColor DarkMagenta
    Write-Output "
    Author = G0urmetD
    version = $version
    "
}
