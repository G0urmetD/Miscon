function Get-ADCSTemplate {
   param(
      [parameter(Position=0)]
      [string]
      $DisplayName,

      [string]
      $Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]
   )
      if ($PSBoundParameters.ContainsKey('DisplayName')) {
         $LDAPFilter = "(&(objectClass=pKICertificateTemplate)(displayName=$DisplayName))"
      } else {
         $LDAPFilter = '(objectClass=pKICertificateTemplate)'
      }

      $ConfigNC     = $((Get-ADRootDSE -Server $Server).configurationNamingContext)
      $TemplatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
      Get-ADObject -SearchScope Subtree -SearchBase $TemplatePath -LDAPFilter $LDAPFilter -Properties * -Server $Server
}
