Function Kill-AzAvdUserSessions {
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
    Param (
        # Name of the Resource Group containing the Azure Virtual Desktop HostPool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$ResourceGroupName,

        # Azure Virtual Desktop HostPool Name (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.DesktopVirtualization/hostpools","ResourceGroupName")]
        [System.String]$HostPoolName,

        [System.String[]]$VMNames,

        [Parameter(Mandatory=$false)]
        [ValidateSet("All","Active","Disconnected")]
        [System.String]$Sessions = "Disconnected",

        [Switch]$SendMessage
    )
    BEGIN {
        #Requires -Modules Az.Accounts,Az.DesktopVirtualization
        Get-AzAuthentication
        Write-Verbose ("[Azure Authentication] {0} Connected to {1} ({2})" -f $SCRIPT:AzAuthentication.Account.Id,$SCRIPT:AzAuthentication.Subscription.Name,$SCRIPT:AzAuthentication.Subscription.Id)

        If ($Sessions -eq "Disconnected" -AND $SendMessage) {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::New(
                    [System.SystemException]::New(("The -SendMessage parameter cannot be used with Disconnected Sessions. Change the -Sessions parameter to 'All' or 'Active'")),
                    "InvalidParameterUsage",
                    [System.Management.Automation.ErrorCategory]::InvalidArgument,
                    ($Sessions)
                )
            )
        }
        ElseIf ($Sessions -eq "All" -AND $SendMessage) {
            Write-Warning ("Using -SendMessage with -Sessions 'All' will only send messages to 'Active' User Sessions")
        }

        Function _CollectUserSessions {
            Param (
                [System.String]$ResourceGroupName,
                [System.String]$HostPoolName,
                [System.String[]]$VMNames,
                [System.String]$Sessions
            )
            # Creates and empty object array for Session Host user session collection
            [System.Collections.Generic.List[Object]]$userSessions = @()
            # Checks the types of Sessions to collect
            # When not matched to 'All' the $Sessions parameter is passed to the filter for session collection
            Switch ($Sessions) {
                "All" {
                    If ([System.String]::IsNullOrEmpty($VMNames)) {
                        Get-AzWvdUserSession -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName | Foreach-Object { $userSessions.Add($_) }
                    }
                    Else {
                        # Loop through each item in $VMNames looking for a match and adding the the object array if found
                        Foreach ($vm in $VMNames) {
                            Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName | Where-Object { $_.Name.Contains($vm) } | Foreach-Object {
                                $shName = $_.Name.Split("/")[-1]
                                Get-AzWvdUserSession -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -SessionHostName $shName | Foreach-Object {
                                    $userSessions.Add($_)
                                }
                            }
                        }
                    }
                }
                Default {
                    If ([System.String]::IsNullOrEmpty($VMNames)) {
                        Get-AzWvdUserSession -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -Filter ("sessionstate eq '{0}'" -f $Sessions) | Foreach-Object { $userSessions.Add($_) }
                    }
                    Else {
                        # Loop through each item in $VMNames looking for a match and adding the the object array if found
                        Foreach ($vm in $VMNames) {
                            Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName | Where-Object { $_.Name.Contains($vm) } | Foreach-Object {
                                $shName = $_.Name.Split("/")[-1]
                                (Get-AzWvdUserSession -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -SessionHostName $shName)| Where-Object {$_.SessionState -eq $Sessions} | Foreach-Object {
                                    $userSessions.Add($_)
                                }
                            }
                        }
                    }
                }
            }
            Return $userSessions
        }

        # logoff message sent to users with active sessions
        $Global:LogOffMessage = (@"
{0}
{1}
{1}  This virtual desktop is being prepared for maintenance.
{1}  If you would like to continue working, please LOGOFF and
{1}  then SIGN-IN again. Do NOT close the window / session
{1}  or simply disconnect.
{1}  
{1}  SHUTDOWN IN {2} MINUTES!
{1}
{0}
"@) # characters used to format the message prompt

        $SessionsRemoved = 0

    }
    PROCESS {
        try {
            # Get the Host Pool object, if not found should throw a terminating error
            $objHostPool = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName -Name $HostPoolName

            $userSessions = _CollectUserSessions -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -VMNames $VMNames -Sessions $Sessions

            If ($userSessions.Count -eq 0) {
                Write-Warning ("No User Sessions found!")
                Return
            }
            Else {
                If ($SendMessage) {
                    For ($i=0; $i -lt 900; $i++) {
                        Write-Progress -Id 7 -Activity "AVD Session Logoff" -Status ("Waiting the 15 minute Grace Period") -SecondsRemaining (900 - $i)
                        Switch($i) {
                            0 {
                                $msgsSent = 0
                                Foreach ($session in $userSessions.Where{$_.SessionState -eq "Active"}) {
                                    Write-Progress -Id 14 -ParentId 7 -Activity ("Sending Logoff Messages") -Status ("Active Sessions: {0}  |  Messages Sent: {1}" -f $userSessions.Where{$_.SessionState -eq "Active"}.Count, $msgsSent)
                                    Send-AzWvdUserSessionMessage `
                                        -SessionHostName $session.Name.Split("/")[1] `
                                        -ResourceGroupName $ResourceGroupName `
                                        -HostPoolName $HostPoolName `
                                        -MessageTitle "!! WARNING - SYSTEM MAINTENANCE !!" `
                                        -MessageBody ($Global:LogOffMessage -f ("/"*80),"//","15") `
                                        -UserSessionId $session.Name.Split("/")[-1]
                                    $msgsSent++
                                }
                                Write-Progress -Id 14 -ParentId 7 -Activity ("Sending Logoff Messages") -Completed
                            }
                            300 {
                                Write-Verbose ("Checking for remaining User Sessions")
                                $userSessions = _CollectUserSessions -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -VMNames $VMNames -Sessions $Sessions
                                If (($userSessions.Where{$_.SessionState -eq "Active"}).Count -eq 0) {
                                    Write-Verbose ("No Sessions Remaining")
                                    Break
                                }
                                Else {
                                    $msgsSent = 0
                                    Foreach ($session in $userSessions.Where{$_.SessionState -eq "Active"}) {
                                        Write-Progress -Id 14 -ParentId 7 -Activity ("Sending Logoff Messages") -Status ("Active Sessions: {0}  |  Messages Sent: {1}" -f $userSessions.Where{$_.SessionState -eq "Active"}.Count, $msgsSent)
                                        Send-AzWvdUserSessionMessage `
                                            -SessionHostName $session.Name.Split("/")[1] `
                                            -ResourceGroupName $ResourceGroupName `
                                            -HostPoolName $HostPoolName `
                                            -MessageTitle "!! WARNING - SYSTEM MAINTENANCE !!" `
                                            -MessageBody ($Global:LogOffMessage -f ("/"*80),"//","10") `
                                            -UserSessionId $session.Name.Split("/")[-1]
                                        $msgsSent++
                                    }
                                    Write-Progress -Id 14 -ParentId 7 -Activity ("Sending Logoff Messages") -Completed
                                }
                            }
                            600 {
                                Write-Verbose ("Checking for remaining User Sessions")
                                $userSessions = _CollectUserSessions -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -VMNames $VMNames -Sessions $Sessions
                                If (($userSessions.Where{$_.SessionState -eq "Active"}).Count -eq 0) {
                                    Write-Verbose ("No Sessions Remaining")
                                    Break
                                }
                                Else {
                                    $msgsSent = 0
                                    Foreach ($session in $userSessions.Where{$_.SessionState -eq "Active"}) {
                                        Write-Progress -Id 14 -ParentId 7 -Activity ("Sending Logoff Messages") -Status ("Active Sessions: {0}  |  Messages Sent: {1}" -f $userSessions.Where{$_.SessionState -eq "Active"}.Count, $msgsSent)
                                        Send-AzWvdUserSessionMessage `
                                            -SessionHostName $session.Name.Split("/")[1] `
                                            -ResourceGroupName $ResourceGroupName `
                                            -HostPoolName $HostPoolName `
                                            -MessageTitle "!! WARNING - SYSTEM MAINTENANCE !!" `
                                            -MessageBody ($Global:LogOffMessage -f ("/"*80),"//","5") `
                                            -UserSessionId $session.Name.Split("/")[-1]
                                        $msgsSent++
                                    }
                                    Write-Progress -Id 14 -ParentId 7 -Activity ("Sending Logoff Messages") -Completed
                                }
                            }
                            #Default { $userSessions = _CollectUserSessions -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -VMNames $VMNames -Sessions $Sessions }
                        }

                        $userSessions = _CollectUserSessions -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -VMNames $VMNames -Sessions $Sessions
                        If ($userSessions.Where{$_.SessionState -eq "Active"}.Count -eq 0) { Break }
                        
                        Foreach ($user in $userSessions.Where{$_.SessionState -eq "Disconnected"}) {
                            Write-Warning ("**Forcibly removing {0} Session Id {1} for {2} on {3}" -f $user.SessionState,$user.Id.Split("/")[-1],$user.UserPrincipalName,$user.Name.Split("/")[1])
                            Remove-AzWvdUserSession -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -SessionHostName $user.Name.Split("/")[1] -Id $user.Id.Split("/")[-1] -Force
                            $SessionsRemoved++
                        }
                        
                        Start-Sleep -Milliseconds 999
                    }
                    Write-Progress -Id 7 -Activity "AVD Session Logoff" -Completed

                    $userSessions = _CollectUserSessions -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -VMNames $VMNames -Sessions $Sessions
                }

                If ($PSCmdlet.ShouldProcess(("{0} User Sessions" -f $userSessions.Count),"Forcibly Remove AVD User Sessions")) {
                    Foreach ($user in $userSessions) {
                        Write-Warning ("Forcibly removing {0} Session Id {1} for {2} on {3}" -f $user.SessionState,$user.Id.Split("/")[-1],$user.UserPrincipalName,$user.Name.Split("/")[1])
                        Remove-AzWvdUserSession -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -SessionHostName $user.Name.Split("/")[1] -Id $user.Id.Split("/")[-1] -Force
                        $SessionsRemoved++
                    }
                }
                Else { Write-Warning ("User Cancelled the Operation!") }
            }
        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
    }
    END {
        Write-Verbose ("Attempted to foricbly remove {0} AVD User Sessions" -f $SessionsRemoved)
        Return [PSCustomObject]@{
            SessionsRemoved = $SessionsRemoved
        }
    }
}