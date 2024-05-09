function Show-Banner {
    <#
    .DESCRIPTION
        Tool Banner.
    .PARAMETER version
        Defines the version.
    #>

    param(
        [string]$version = "1.6.12"
    )

    Write-Output "
    ___  ____                     
    |  \/  (_)                    
    | .  . |_ ___  ___ ___  _ __  
    | |\/| | / __|/ __/ _ \| '_ \ 
    | |  | | \__ \ (_| (_) | | | |
    \_|  |_/_|___/\___\___/|_| |_|
    
    Author = G0urmetD
    version = $version
    "
}
