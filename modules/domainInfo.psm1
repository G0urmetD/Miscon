function Get-DomainInfo {
    $domainInfo = @{
        DomainName = (Get-ADDomain).DNSRoot
        DomainController = (Get-ADDomainController -Discover -Service PrimaryDC).HostName
        DomainFunctionalLevel = (Get-ADDomain).DomainMode
        ForestFunctionalLevel = (Get-ADForest).ForestMode
        DomainControllers = (Get-ADDomainController -Filter *).HostName
        Sites = (Get-ADReplicationSite -Filter *).Name
        SitesCount = @(Get-ADReplicationSite -Filter *).Count
        #DomainAdmins = (Get-ADGroup -Filter {Name -like "Domain Admins" -or Name -like "Domanen-Admins"}).Members | Get-ADUser | Select-Object -ExcludeProperty SamAccountName
        #DomainAdminsCount = @(Get-ADGroup -Filter {Name -like "Domain Admins" -or Name -like "Domanen-Admins"}).Members.Count
        UsersCount = @(Get-ADUser -Filter *).Count
        ComputersCount = @(Get-ADComputer -Filter *).Count
    }
    return $domainInfo
}