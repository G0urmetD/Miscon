# if current shell not as admin -> start a shell as admin and execute script
if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Prompt the user to elevate the script
    $arguments = "& '" + $myInvocation.MyCommand.Definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    exit
}

Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
Write-Host " Install Requirements started ..."
Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
Write-Host " Install & Import ActiveDirectory module ..."
Install-Module -Name ActiveDirectory -Force
Import-Module -Name ActiveDirectory -Force

Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
Write-Host " Install & Import GroupPolicy module ..."
Install-Module -Name GroupPolicy -Force
Import-Module -Name GroupPolicy -Force
