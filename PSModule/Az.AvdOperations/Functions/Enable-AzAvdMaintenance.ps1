Function Enable-AzAvdMaintanence {
    <#
        .SYNOPSIS
            Puts Azure Virtual Desktop Session Hosts into 'maintenance'
        .DESCRIPTION
            This cmdlet targets a specific host pool and session hosts, changes their Azure maintenance tag to TRUE and turns ON drain mode to prevent new connections. This cmdlet will also optionally log off user sessions based on type and can send active users a notification message. Enabling 'maintenance' is additionally used to ensure Session Hosts are not managed by the AutoScale system.
        .EXAMPLE
            Enable-AzAvdMaintanence -ResourceGroupName <string> -HostPoolName <string> -ResourceType <string> [-VMNames <string[]>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]

        .EXAMPLE
            Enable-AzAvdMaintanence [-ResourceGroupName] <string> [-HostPoolName] <string> [-ResourceType] <string> [-LogoffSessions] [-SessionType] <string> [-Notification] <string> [[-VMNames] <string[]>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact="High",DefaultParameterSetName="Default")]
    Param (
        # Name of the Resource Group containing the Azure Virtual Desktop HostPool (supports tab completion)
        [Parameter(Mandatory=$true,ParameterSetName="Default",HelpMessage="Type the name of the ResourceGroup where the Host Pool resource is located")]
        [Parameter(Mandatory=$true,ParameterSetName="Logoff",Position=0,HelpMessage="Type the name of the ResourceGroup where the Host Pool resource is located")]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$ResourceGroupName,

        # Azure Virtual Desktop HostPool Name (supports tab completion)
        [Parameter(Mandatory=$true,ParameterSetName="Default",HelpMessage="Type the name of the Host Pool resource to target")]
        [Parameter(Mandatory=$true,ParameterSetName="Logoff",Position=1,HelpMessage="Type the name of the Host Pool resource to target")]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.DesktopVirtualization/hostpools","ResourceGroupName")]
        [System.String]$HostPoolName,

        # Select to only disable Azure Maintenance tag on Session Hosts vs All resources
        [Parameter(Mandatory=$true,ParameterSetName="Default",HelpMessage="Choose which resource type to target: 'All' or 'SessionHostsOnly'")]
        [Parameter(Mandatory=$true,ParameterSetName="Logoff",Position=2,HelpMessage="Choose which resource type to target: 'All' or 'SessionHostsOnly'")]
        [ValidateSet("All","SessionHostsOnly")]
        [System.String]$ResourceType,

        # Any sessions will be force logged off after a default period of 15 minutes.
        [Parameter(Mandatory=$false,ParameterSetName="Logoff",Position=3)]
        [Switch]$LogoffSessions,

        # When using the -LogoffSessions switch, choose the type of sessions to target: 'All', 'Active', or 'Disconnected'
        [Parameter(Mandatory=$true,ParameterSetName="Logoff",Position=4,HelpMessage="Choose the type of sessions to target: 'All', 'Active', or 'Disconnected'")]
        [ValidateSet("All","Active","Disconnected")]
        [System.String]$SessionType,

        # When using the -LogoffSessions switch, choose the type of notification to send: 'None', 'SendMessage'
        [Parameter(Mandatory=$true,ParameterSetName="Logoff",Position=5,HelpMessage="Choose the type of notification to send: 'None' or 'SendMessage'")]
        [ValidateSet("None","SendMessage")]
        [System.String]$Notification,

        # Optionally provide the VM Name(s) to target in the Host Pool. If used, it cannot be empty. Will accept an array of names.
        [Parameter(Mandatory=$false,ParameterSetName="Default")]
        [Parameter(Mandatory=$false,ParameterSetName="Logoff",Position=6)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]$VMNames,

        # Use this switch to enable maintenance on all session hosts regardless of current tagging state.
        [Parameter(Mandatory=$false)]
        [Switch]$Force
    )
    BEGIN {
        #Requires -Modules Az.Accounts,Az.DesktopVirtualization
        Get-AzAuthentication
        Write-Verbose ("[Azure Authentication] {0} Connected to {1} ({2})" -f $SCRIPT:AzAuthentication.Account.Id,$SCRIPT:AzAuthentication.Subscription.Name,$SCRIPT:AzAuthentication.Subscription.Id)

        If ($LogoffSessions) {

            If ($SessionType -eq "Disconnected" -AND $Notification -eq "SendMessage") {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::New(
                        [System.SystemException]::New(("The parmeter, '-Notification SendMessage', cannot be used with Disconnected Session Types. Change the -SessionType parameter to 'All' or 'Active'")),
                        "InvalidParameterUsage",
                        [System.Management.Automation.ErrorCategory]::InvalidArgument,
                        (("SessionType: {0}" -f $SessionType))
                    )
                )
            }
            ElseIf ($SessionType -eq "All" -AND $Notification -eq "SendMessage") { Write-Warning ("The parmeter, '-Notification SendMessage', with -SessionType 'All' will only send messages to 'Active' User Sessions") }

        }
        Else {
            $notifyParam = $PSCmdlet.MyInvocation.BoundParameters.ContainsKey("Notification")
            $typeParam = $PSCmdlet.MyInvocation.BoundParameters.ContainsKey("SessionType")

            If ($notifyParam -OR $typeParam) {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::New(
                        [System.SystemException]::New(("The parmeter, '-Notification' or '-SessionType', require the '-LogoffSessions' switch parameter. Add the switch and re-run or remove the invalid parameters")),
                        "InvalidParameterUsage",
                        [System.Management.Automation.ErrorCategory]::InvalidArgument,
                        (("Notification: {0}  |  SessionType: {1}" -f $notifyParam,$typeParam))
                    )
                )
            }
        }
    }
    PROCESS {
        try {
            # collection the virtual machines
            Write-Verbose ("[{0}] Gathering Session Hosts" -f $HostPoolName)
            [System.Collections.Generic.List[System.Object]]$vmCollection = @()
            If ([System.String]::IsNullOrEmpty($VMNames)) { Get-AzVM -ResourceGroupName $ResourceGroupName -Status | ForEach-Object { $vmCollection.Add($_) | Out-Null } }
            Else { (Get-AzVM -ResourceGroupName $ResourceGroupName -Status).Where{$_.Name -in $VMNames} | ForEach-Object { $vmCollection.Add($_) | Out-Null } }
            
            # loop through the virtual machines and add the session host information to the vm object
            $i = 0
            $sessionHostCount = 0
            Foreach ($virtualMachine in $vmCollection) {
                Write-Progress -Activity ("[{0}] Gathering Session Hosts" -f $HostPoolName.ToUpper()) -Status ("Session Hosts Collected: {0}" -f $sessionHostCount) -CurrentOperation $virtualMachine.Name -PercentComplete (($i / $vmCollection.Count) * 100)
                $sessionHost = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName | Where-Object {$_.ResourceId -eq $virtualMachine.Id}
                
                If ($sessionHost) {
                    $sessionHostCount++
                    $virtualMachine | Add-Member -NotePropertyName SessionHost -NotePropertyValue $sessionHost
                    $virtualMachine | Add-Member -NotePropertyName Updated -NotePropertyValue $false
                    If ($LogoffSessions) { $virtualMachine | Add-Member -NotePropertyName LogoffUsers -NotePropertyValue $true }
                    Else { $virtualMachine | Add-Member -NotePropertyName LogoffUsers -NotePropertyValue $false }
                }
                Else {
                    Write-Warning ("[{0}] Unable to match Virtual Machine object to Session Host object, removing the VM from processing collection!" -f $virtualMachine.Name)
                    If ($null -eq $missingVMs) {
                        $missingVMs = [System.Collections.Generic.List[System.Object]]@()
                        $missingVMs.Add($virtualMachine)
                    }
                    Else { $missingVMs.Add($virtualMachine) }
                }
                $i++
            }

            Write-Progress -Activity ("[{0}] Gathering Session Hosts" -f $HostPoolName.ToUpper()) -Completed
            If ($missingVMs.Count -gt 0) { $missingVMs | ForEach-Object {$vmCollection.Remove($_) | Out-Null} }

            $vmMaintenanceHash = $vmCollection | Group-Object -Property {$_.Tags["WVD-Maintenance"]} -AsHashTable -AsString
            If ($Force) { $shCollection = $vmCollection }
            Else { $shCollection = $vmMaintenanceHash["False"] }

            If ($shCollection.Count -eq 0) { Write-Warning "No Session Hosts found!" }
            Else {

                If ($LogoffSessions) {
                    $ShouldProcessMsg = "ENABLE maintenace and LOGOFF current sessions"
                    Write-Warning ("PROCEEDING WILL FORIBLY LOGOFF USERS AFTER A 15 MINUTE GRACE PERIOD!")
                }
                Else {
                    $ShouldProcessMsg = "ENABLE maintenace and drain mode"
                }

                # prevent this prompt by using -Confirm $false
                If ($PSCmdlet.ShouldProcess(("{0} WVD Session Hosts" -f $shCollection.Count),$ShouldProcessMsg)) {

                    $hpTagUpdated = $false
                    If ($ResourceType -eq "All") {
                        Write-Verbose ("[{0}] Updating Host Pool 'WVD-Maintenance' Tag" -f $HostPoolName)
                        $HostPool = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName
                        try {
                            Update-AzTag -ResourceId $HostPool.Id -Tag @{"WVD-Maintenance" = $true} -Operation Merge | Out-Null
                            $hpTagUpdated = $true
                            Write-Verbose ("[{0}] Successfully updated Azure Tag" -f $HostPoolName)
                        }
                        catch {
                            Write-Warning ("Failed to update Azure Tag for Host Pool: {0}" -f $HostPoolName)
                            Continue
                        }
                    }
                    
                    $x = 0
                    Foreach ($virtualMachine in $shCollection) {
                        Write-Progress -Id 42 -Activity ("[{0}] Updating Maintenance Tag" -f $HostPoolName) -Status ("Session Hosts Updated: {0}" -f $x) -CurrentOperation $virtualMachine.SessionHost.Name -PercentComplete (($x / $shCollection.Count) * 100)
                        try {
                            $tagUpdate = @{"WVD-Maintenance" = $true}
                            Update-AzTag -ResourceId $virtualMachine.Id -Tag $tagUpdate -Operation Merge | Out-Null
                            Update-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -Name $virtualMachine.SessionHost.Name.Split("/")[-1] -AllowNewSession:$false | Out-Null
                            Write-Verbose ("[{0}] Successfully updated Azure Tag on Session Host: {1}" -f $HostPoolName, $virtualMachine.SessionHost.Name.Split("/")[-1])
                            $virtualMachine.Updated = $true
                            $x++
                        }
                        catch {
                            Write-Warning ("Failed to update Azure Tag for Session Host: {0}" -f $virtualMachine.SessionHost.Name.Split("/")[-1])
                            Continue
                        }
                    }
                    Write-Progress -Id 42 -Activity ("[{0}] Updating Maintenance Tag" -f $HostPoolName) -Completed

                    $shKillCollection = $shCollection | Where-Object {$_.Updated -eq $true -AND $_.LogoffUsers -eq $true}
                    If ($shKillCollection.Count -gt 0) {
                        If ($Notification -eq "SendMessage") { $killResults = Kill-AzAvdUserSessions -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -VMNames $shKillCollection.Name -Sessions $SessionType -SendMessage -Confirm:$false }
                        Else { $killResults = Kill-AzAvdUserSessions -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -VMNames $shKillCollection.Name -Sessions $SessionType -Confirm:$false }
                    }
                    Else { Write-Warning ("No Session Hosts were updated or flagged for user logoff!") }
                }
                Else { Write-Warning "User aborted WVD Maintenance operation!" }
            }
        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
    }
    END {
        If ($shCollection.Count -gt 0) {
            $results = [PSCustomObject]@{
                Operation = $PSCmdlet.MyInvocation.MyCommand.Name
                ResourceGroup = $ResourceGroupName
                HostPool = $HostPoolName
                HostPoolUpdated = $hpTagUpdated
                SessionHostsUpdated = ($shCollection | Where-Object {$_.Updated -eq $true}).Count
                SessionHostsSkipped = ($shCollection | Where-Object {$_.Updated -eq $false}).Count
                SessionsRemoved = $killResults.SessionsRemoved
            }
            Return $results
        }
    }
}