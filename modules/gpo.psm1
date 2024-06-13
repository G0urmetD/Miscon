function Get-GPOWmiFilter {
    <#
    .Synopsis
       Gets all Group Policy Filters or by name
    .DESCRIPTION
       This cmdlet depends on the GroupPolicy module
    .EXAMPLE
       Get-GPOWmiFilter
    
       Lists all (if any) WMIFilter configured in Group Policy Management
    .FUNCTIONALITY
       Linking GPOs with WMIFilters
    .NOTES
        Thanks to: Created by Tore.Groneng@firstpoint.no @ToreGroneng 2016
    #>
    [cmdletbinding()]
    Param(
       [Parameter(ValueFromPipeline)]
       [string[]]$Name = "*"
    )
    BEGIN {
       $f = $MyInvocation.InvocationName
 
       if(-not (Get-Module -Name GroupPolicy))
       {
          Import-Module -Name GroupPolicy -ErrorAction Stop -Verbose:$false
       }
 
       Write-Verbose -Message "$f - START"
       $GPdomain = New-Object Microsoft.GroupPolicy.GPDomain
       $SearchFilter = New-Object Microsoft.GroupPolicy.GPSearchCriteria
       Write-Verbose -Message "$f - Searching for WmiFilters"
       $allWmiFilters = $GPdomain.SearchWmiFilters($SearchFilter)
       Write-Verbose -Message "$f - Found $($allWmiFilters.Count) filters"
    }
 
    PROCESS {
       foreach($FilterName in $Name)
       {
          Write-Verbose -Message "$f - Looking for $FilterName"
          $allWmiFilters | Where-Object Name -like $FilterName
       }
    }
 
    END {
       Write-Verbose -Message "$f - END"
    }
 }

function Test-GPOs {
    # read GPO into array
    Write-Host -ForegroundColor Cyan "[INFO]" -NoNewline
    Write-Host " Enumerate domain GPO's ..."
    $domainGPOs = Get-GPO -All -Domain $domain
    $domainGPOs | Select-Object Id,DisplayName,DomainName,Owner,GpoStatus,ModificationTime,Description | Format-Table

    # grep wmifilters
    Write-Host -ForegroundColor Cyan "[INFO]" -NoNewline
    Write-Host " Enumerate domain GPO WMI filter ..."
    $domainGPOWmiFilter = Get-GPOWmiFilter
    $domainGPOWmiFilter
}