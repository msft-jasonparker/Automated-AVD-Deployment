Function Invoke-AzAvdSessionManager {
    <#
        .SYNOPSIS
            Searches for and removes sessions from Host Pools in a subscription.
        .DESCRIPTION
        This cmdlet is good for finding users Azure Virtual Desktop sessions in all Host Pools and search by username or user principal name. Once found, user sessions can be removed from the Session Host(s).
    #>
    [CmdletBinding()]
    Param (
        # Name of the Subscription where the Azure Virtual Desktop Host Pools can be found (supports tab completion)
        [Parameter(Mandatory=$true)]
        [ArgumentCompleter({
            Param($CommandName,$ParameterName,$WordsToComplete,$CommandAst,$FakeBoundParameters)
            Get-AzSubscription | Where-Object {$_.Name -like "$WordsToComplete*"} | Select-Object -ExpandProperty Name
        })]
        [String]$SubscriptionName
    )
    BEGIN {
        #Requires -Modules Az.Accounts,Az.DesktopVirtualization
        Get-AzAuthentication
        Write-Verbose ("[Azure Authentication] {0} Connected to {1} ({2})" -f $SCRIPT:AzAuthentication.Account.Id,$SCRIPT:AzAuthentication.Subscription.Name,$SCRIPT:AzAuthentication.Subscription.Id)
        Function _GetAzAvdUserSessions {
            Write-Host (" Getting Azure Virtual Desktop Host Pools...")
            $HPs = Get-AzWvdHostPool -Verbose:$false -Debug:$false | Select-Object @{l="Name";e={$_.Name.Split("/")[-1]}},@{l="ResourceGroupName";e={$_.Id.Split("/")[4]}}
            If ($HPs.Count -gt 0) {
                Write-Host ("  >> Found {0} Azure Virtual Desktop Host Pools" -f $HPs.Count)
                [System.Collections.ArrayList]$Sessions = @()
                Foreach ($HP in $HPs) {
                    Write-Host ("  >> [{0}] Collecting Host Pool User Session Information" -f $HP.Name)
                    Get-AzWvdUserSession -HostPoolName $HP.Name -ResourceGroupName $HP.ResourceGroupName | ForEach-Object {
                        $sessionObject = [PSCustomObject][Ordered]@{
                            UserPrincipalName = $_.UserPrincipalName
                            UserName = $_.ActiveDirectoryUserName
                            HostPool = $HP.Name
                            ResourceGroupName = $HP.ResourceGroupName
                            SessionHost = $_.Name.Split("/")[1]
                            Id = $_.Name.Split("/")[-1]
                            Duration = ([DateTime]::Now).Subtract($_.CreateTime.ToLocalTime())
                            SessionState = $_.SessionState
                        }
                        [Void]$Sessions.Add($sessionObject)
                    }
                }
                Write-Host "`n`r"
                Write-Verbose ("Collected {0} User Sessions from {1} Host Pools" -f $Sessions.Count,$HPs.Count)
                Return $Sessions
            }
            Else {
                Write-Warning ("No WVD Host Pools found in the {0} Subscription" -f $SubscriptionName)
                Return
            }
        }
    }
    PROCESS {
        Show-Menu -Title (" Azure Virtual Desktop User Session Manager") -Style Full -Color White -DisplayOnly
        Set-AzContext -Subscription $SubscriptionName | Out-Null
        
        Do {
            If ($null -eq $Sessions) { $Sessions = _GetAzAvdUserSessions }
            Else {
                Write-Warning ("User Session data is not empty ({0} Sessions)" -f $Sessions.Count)
                Switch (Get-ChoicePrompt -Message "`nDo you want to get a fresh collection of User Sessions?" -OptionList "&Yes","&No" -Default 1) {
                    0 {
                        Clear-Host
                        $Sessions = _GetAzAvdUserSessions
                    }
                    1 {
                        Clear-Host
                        Write-Verbose ("Using current User Session data ({0} Sessions)" -f $Sessions.Count)
                    }
                }
            }
            
            If ($Sessions.Count -eq 0) { Write-Warning ("No User Sessions Found") }
            Else {
                $HostPools = $Sessions | Group-Object HostPool -NoElement -AsHashTable -AsString
                Show-Menu -Title (" Found {0} User Sessions from {1} Host Pools" -f $Sessions.Count,$HostPools.Count) -Style Mini -Color Yellow -DisplayOnly
                Switch (Get-ChoicePrompt -Message "Search by UserName or UserPrincipalName?" -OptionList "&UserName","User&PrincipalName","&Quit" -Default 1) {
                    0 {
                        $property = "UserName"
                        $searchString = Show-Menu -Title " Enter the full or partial Active Directory UserName" -Menu "UserName" -Style Info -Color Cyan
                    }
                    1 {
                        $property = "UserPrincipalName"
                        $searchString = Show-Menu -Title " Enter the full or partial Active Directory UserPrincipalName" -Menu "UserPrincipalName" -Style Info -Color Cyan
                    }
                    2 { Return }
                }
                $sessionMatches = $Sessions.Where{$_.$property -match $searchString}
                Write-Verbose ("Found {0} Sessions by {1} Property" -f $sessionMatches.Count,$property)
                If ($sessionMatches.Count -eq 0) { Write-Warning ("No matches found using '{0}', refine the search criteria." -f $searchString) }
                ElseIf ($sessionMatches.Count -gt 10) { Write-Warning ("Too many matches found ({0}) using '{1}', refine the search criteria." -f $sessionMatches.Count,$searchString) }
                Else {
                    $Selection = "`n"
                    $Range = 1..($sessionMatches.Count)
                    For ($i = 0; $i -lt $sessionMatches.Count;$i++) {$Selection += (" [{0}] {1}`t{2}`t{3}`t{4}`n" -f ($i+1),$sessionMatches[$i].$property,$sessionMatches[$i].SessionHost,$sessionMatches[$i].SessionState,$sessionMatches[$i].Duration)}
                    $Selection += ("`n Please select a {0} or [Q] to Quit" -f $property)

                    Do { $Choice = Show-Menu -Title " Remove WVD User Session" -Menu $Selection -Style Mini -Color White -ClearScreen }
                    Until (($Range -contains $Choice) -OR ($Choice -eq "Q"))
                    If ($Choice -ne "Q") {
                        $Choice = $Choice - 1

                        Write-Output "`n" $sessionMatches[$Choice] | Format-Table -Autosize

                        $SessionHostStatus = Get-AzWvdSessionHost -HostPoolName $sessionMatches[$Choice].HostPool -ResourceGroupName $sessionMatches[$Choice].ResourceGroupName -Name $sessionMatches[$Choice].SessionHost | Select-Object -ExpandProperty Status
                        If ($SessionHostStatus -eq "Available") { 
                            Write-Warning ("Forcibly removing {0} Session Id {1} for {2} on {3}" -f $sessionMatches[$Choice].SessionState,$sessionMatches[$Choice].id,$sessionMatches[$Choice].UserPrincipalName,$sessionMatches[$Choice].SessionHost)
                            Remove-AzWvdUserSession -HostPoolName $sessionMatches[$Choice].HostPool -ResourceGroupName $sessionMatches[$Choice].ResourceGroupName -SessionHostName $sessionMatches[$Choice].SessionHost -Id $sessionMatches[$Choice].Id -Force -Confirm
                        }
                        Else { Write-Warning ("[{0}] Session Host Agent Status is: {1}, Session Host should be drained and rebooted" -f $sessionMatches[$Choice].SessionHost,$SessionHostStatus) }
                    }
                }
            }
                    
            $Done = Get-ChoicePrompt -Message "`nSearch for another User Session?" -OptionList "&Yes","&No"
        } Until ($Done -eq 1)
    }
}