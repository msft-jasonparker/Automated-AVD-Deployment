Function Get-ADAttributes {
    [CmdletBinding()]
    Param (
           [String]$Property,
           [String]$Value,
           [Switch]$AllProperties,
           [Switch]$Search
    )

    $userDomainSplit = $env:USERDNSDOMAIN.Split(".")
    $ADSearch = New-Object System.DirectoryServices.DirectorySearcher
    $ADSearch.ClientTimeout = "00:00:15"
    $ADSearch.ServerTimeLimit = "00:00:30"
    $ADSearch.ServerPageTimeLimit = "00:00:15"
    $ADSearch.SearchRoot = ("GC://dc={0},dc={1}" -f $userDomainSplit[-2],$userDomainSplit[-1])

    If ($AllProperties) {
           #Write-Debug "Check AllProperties Switch"
           $ADSearch.Filter = "(&($Property=$Value))"
           $ADInfo = $ADSearch.FindOne() | Select-Object -ExpandProperty Properties
           Return $ADInfo
    }
    Else {
           $colPropList = @(
                  "givenname", "sn", "samaccountname", "mail", "department", "l", "st", "physicaldeliveryofficename",
                  "telephonenumber", "distinguishedname", "canonicalname", "userprincipalname", "mailnickname",
                  "extensionattribute6", "extensionattribute7", "extensionattribute8", "objectGUID", "objectCategory", "objectClass", "pwdlastset",
                  "lastlogontimestamp", "homemdb", "proxyaddresses", "publicdelegates", "publicdelegatesbl", "msexchrecipienttypedetails",
                  "usersmimecertificate", "userAccountControl", "legacyexchangedn", "whencreated", "whenchanged"
           )
   
           $ADSearch.PropertiesToLoad.AddRange($colPropList)

           If ($Search) {
                  #Write-Debug "Test Search"
                  $ADSearch.Filter = "(&($Property=*$Value*))"
                  $ADResult = $ADSearch.FindAll()
                  If ($ADResult.Count -eq 1) {
                         $ADInfo = $ADResult | Select-Object `
                         @{N = "samaccountname"; E = { $_.Properties["samaccountname"] } },
                         @{N = "mail"; E = { $_.Properties["mail"] } },
                         @{N = "distinguishedname"; E = { $_.Properties["distinguishedname"] } },
                         @{N = "userprincipalname"; E = { $_.Properties["userprincipalname"] } },
                         @{N = "mailnickname"; E = { $_.Properties["mailnickname"] } },
                         @{N = "extensionattribute6"; E = { $_.Properties["extensionattribute6"] } },
                         @{N = "extensionattribute7"; E = { $_.Properties["extensionattribute7"] } },
                         @{N = "extensionattribute8"; E = { $_.Properties["extensionattribute8"] } },
                         @{N = "objectGUID"; E = { $_.Properties["objectGUID"] } },
                         @{N = "objectCategory"; E = { $_.Properties["objectCategory"] } },
                         @{N = "objectClass"; E = { $_.Properties["objectClass"] } },
                         @{N = "proxyaddresses"; E = { $_.Properties["proxyaddresses"] } },
                         @{N = "usersmimecertificate"; E = { $_.Properties["usersmimecertificate"] } },
                         @{N = "msexchrecipienttypedetails"; E = { $_.Properties["msexchrecipienttypedetails"] } },
                         @{N = "whencreated"; E = { $_.Properties["whencreated"] } },
                         @{N = "whenchanged"; E = { $_.Properties["whenchanged"] } },
                         @{N = "canonicalname"; E = { $_.Properties["canonicalname"] } },
                         @{N = "givenname"; E = { $_.Properties["givenname"] } },
                         @{N = "sn"; E = { $_.Properties["sn"] } },
                         @{N = "department"; E = { $_.Properties["department"] } },
                         @{N = "l"; E = { $_.Properties["l"] } },
                         @{N = "st"; E = { $_.Properties["st"] } },
                         @{N = "physicaldeliveryofficename"; E = { $_.Properties["physicaldeliveryofficename"] } },
                         @{N = "telephonenumber"; E = { $_.Properties["telephonenumber"] } },
                         @{N = "useraccountcontrol"; E = { $_.Properties["useraccountcontrol"] } },
                         @{N = "homemdb"; E = { $_.Properties["homemdb"] } },
                         @{N = "publicdelegates"; E = { $_.Properties["publicdelegates"] } },
                         @{N = "publicdelegatesbl"; E = { $_.Properties["publicdelegatesbl"] } },
                         @{N = "pwdlastset"; E = { $_.Properties["pwdlastset"] } },
                         @{N = "lastlogontimestamp"; E = { $_.Properties["lastlogontimestamp"] } },
                         @{N = "legacyexchangedn"; E = { $_.Properties["legacyexchangedn"] } }

                         Return $ADInfo
                  }
                  ElseIf ($ADResult.Count -gt 1) {
                         Return $ADResult
                  }
                  Else {
                         ##Write-Warning "No Results Found!"
                  }
           }
           Else {
                  #Write-Debug "No Search"
                  $ADSearch.Filter = "(&($Property=$Value))"
                  $ADResult = $ADSearch.FindOne()
                  $ADInfo = $ADResult | Select-Object `
                  @{N = "samaccountname"; E = { $_.Properties["samaccountname"] } },
                  @{N = "mail"; E = { $_.Properties["mail"] } },
                  @{N = "distinguishedname"; E = { $_.Properties["distinguishedname"] } },
                  @{N = "userprincipalname"; E = { $_.Properties["userprincipalname"] } },
                  @{N = "mailnickname"; E = { $_.Properties["mailnickname"] } },
                  @{N = "extensionattribute6"; E = { $_.Properties["extensionattribute6"] } },
                  @{N = "extensionattribute7"; E = { $_.Properties["extensionattribute7"] } },
                  @{N = "extensionattribute8"; E = { $_.Properties["extensionattribute8"] } },
                  @{N = "objectGUID"; E = { $_.Properties["objectGUID"] } },
                  @{N = "objectCategory"; E = { $_.Properties["objectCategory"] } },
                  @{N = "objectClass"; E = { $_.Properties["objectClass"] } },
                  @{N = "proxyaddresses"; E = { $_.Properties["proxyaddresses"] } },
                  @{N = "usersmimecertificate"; E = { $_.Properties["usersmimecertificate"] } },
                  @{N = "msexchrecipienttypedetails"; E = { $_.Properties["msexchrecipienttypedetails"] } },
                  @{N = "whencreated"; E = { $_.Properties["whencreated"] } },
                  @{N = "whenchanged"; E = { $_.Properties["whenchanged"] } },
                  @{N = "canonicalname"; E = { $_.Properties["canonicalname"] } },
                  @{N = "givenname"; E = { $_.Properties["givenname"] } },
                  @{N = "sn"; E = { $_.Properties["sn"] } },
                  @{N = "department"; E = { $_.Properties["department"] } },
                  @{N = "l"; E = { $_.Properties["l"] } },
                  @{N = "st"; E = { $_.Properties["st"] } },
                  @{N = "physicaldeliveryofficename"; E = { $_.Properties["physicaldeliveryofficename"] } },
                  @{N = "telephonenumber"; E = { $_.Properties["telephonenumber"] } },
                  @{N = "useraccountcontrol"; E = { $_.Properties["useraccountcontrol"] } },
                  @{N = "homemdb"; E = { $_.Properties["homemdb"] } },
                  @{N = "publicdelegates"; E = { $_.Properties["publicdelegates"] } },
                  @{N = "publicdelegatesbl"; E = { $_.Properties["publicdelegatesbl"] } },
                  @{N = "pwdlastset"; E = { $_.Properties["pwdlastset"] } },
                  @{N = "lastlogontimestamp"; E = { $_.Properties["lastlogontimestamp"] } },
                  @{N = "legacyexchangedn"; E = { $_.Properties["legacyexchangedn"] } }

                  Return $ADInfo
           }
    }
} 