Function Enable-AzWvdMaintanence {
    <#
        .SYNOPSIS
            Puts a specific group of session hosts in a host pool into 'maintenance'
        .DESCRIPTION
            This function targets a specific host pool and group of session hosts, changes their Azure maintenance tag to TRUE and turns on drain mode to prevent new connections. Use of this function is for session host redeployment for monthly patching or session host recycling.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
    Param (
        # Name of the Resource Group of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$ResourceGroupName,

        # Name of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.DesktopVirtualization/hostpools", "ResourceGroupName")]
        [System.String]$HostPoolName,

        # Group of Session Hosts to target (A or B)
        [Parameter(Mandatory = $true)]
        [ValidateSet("A", "B", "ALL")]
        [System.String]$SessionHostGroup,

        [Parameter(Mandatory = $false)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$LogAnalyticsResourceGroup,

        [Parameter(Mandatory = $false)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.OperationalInsights/workspaces", "LogAnalyticsResourceGroup")]
        [System.String]$LogAnalyticsWorkspace
    )
    BEGIN {
        #Requires -Modules @{ ModuleName = "Az.DesktopVirtualization"; ModuleVersion = "2.0.0" }
        
        $azContext = Get-AzContext
        $CorrelationId = [System.Guid]::NewGuid()
    }
    PROCESS {
        try {
            # variables for writing data to log analytics
            $azLogAnalyticsId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspace).CustomerId.ToString()
            $azLogAnalyticsKey = (Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspace).PrimarySharedKey
            
            # logoff message sent to users with active sessions
            $Global:LogOffMessage = (@"
{0}
{1}
{1}  This virtual desktop is being prepared for maintenance.
{1}  If you would like to continue working, please LOGOFF and
{1}  then SIGN-IN again. Do NOT close the window / session
{1}  or simply disconnect.
{1}  
{1}  SHUTDOWN IN 5 MINUTES!
{1}
{0}
"@ -f ("/" * 80), "//") # characters used to format the message prompt

            # collection the virtual machines based on WVD-Group tag
            Write-Verbose ("[{0}] Gathering Session Hosts from Group {1}" -f $HostPoolName, $SessionHostGroup)
            [System.Collections.Generic.List[System.Object]]$vmCollection = @()
            If ($SessionHostGroup -eq "ALL") { Get-AzVM -ResourceGroupName $ResourceGroupName -Status | ForEach-Object { $vmCollection.Add($_) | Out-Null } }
            Else { Get-AzVM -ResourceGroupName $ResourceGroupName -Status | Where-Object { $_.Tags["WVD-Group"] -eq $SessionHostGroup } | ForEach-Object { $vmCollection.Add($_) | Out-Null } }
            
            # loop through the virtual machines and add the session host information to the vm object
            $i = 0
            $sessionHostCount = 0
            Foreach ($virtualMachine in $vmCollection) {
                Write-Progress -Activity ("[{0}] Gathering Session Hosts from Group {1}" -f $HostPoolName, $SessionHostGroup.ToUpper()) -Status ("Session Hosts Collected: {0}" -f $sessionHostCount) -CurrentOperation $virtualMachine.Name -PercentComplete (($i / $vmCollection.Count) * 100)
                $sessionHost = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName | Where-Object { $_.ResourceId -eq $virtualMachine.Id }
                
                If ($sessionHost) {
                    $sessionHostCount++
                    $virtualMachine | Add-Member -NotePropertyName SessionHost -NotePropertyValue $sessionHost
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
            Write-Progress -Activity ("[{0}] Gathering Session Hosts from Group {1}" -f $HostPoolName, $SessionHostGroup.ToUpper()) -Completed
            If ($missingVMs.Count -gt 0) { $missingVMs | ForEach-Object { $vmCollection.Remove($_) | Out-Null } }

            If ($vmCollection.Count -eq 0) { Write-Warning "No Session Hosts found to put into maintenance!" }

            Write-Warning ("PLEASE REVIEW THE COMMENT BASED HELP FOR THIS COMMAND - PROCEEDING WILL FORIBLY LOGOFF USERS AFTER A 5 MINUTE GRACE PERIOD!")

            # prevent this prompt by using -Confirm $false
            If ($PSCmdlet.ShouldProcess(("{0} WVD Session Hosts" -f $vmCollection.Count), "ENABLE maintenace and DRAIN current sessions")) {
                # loop through each vm in the collection, update the maintenance/dsc tag and turn off drain mode
                If ($SessionHostGroup -eq "ALL") {
                    Write-Verbose ("Updating 'WVD-Maintenance' Tag on Host Pool {0}" -f $HostPoolName)
                    $HostPool = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName
                    Update-AzTag -ResourceId $HostPool.Id -Tag @{"WVD-Maintenance" = $true } -Operation Merge | Out-Null
                    $logEntry = [PSCustomObject]@{
                        Timestamp         = [DateTime]::UtcNow.ToString('o')
                        CorrelationId     = $correlationId
                        Computer          = $env:COMPUTERNAME
                        UserName          = $azContext.Account.Id
                        EntryType         = "INFO"
                        Subscription      = $azContext.Subscription.Name
                        ResourceGroupName = $ResourceGroupName
                        HostPoolName      = $HostPoolName
                        SessionHostGroup  = $SessionHostGroup.ToUpper()
                        'WVD-Maintenance' = 'True'
                    }
                    New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_Maintenance_CL" -logMessage $logEntry -Verbose:$false
                }
                
                $x = 0
                $msgsSent = 0
                Foreach ($virtualMachine in $vmCollection) {
                    Write-Progress -Id 42 -Activity ("[{0}] Updating Maintenance Tag, Enabling Drain Mode and sending Logoff Message" -f $HostPoolName) -Status ("Session Hosts Updated: {0} | Messages Sent: {1}" -f $x, $msgsSent) -CurrentOperation $virtualMachine.SessionHost.Name -PercentComplete (($x / $vmCollection.Count) * 100)
                    $tagUpdate = @{"WVD-Maintenance" = $true }
                    Update-AzTag -ResourceId $virtualMachine.Id -Tag $tagUpdate -Operation Merge | Out-Null

                    If ($virtualMachine.SessionHost) {
                        Write-Verbose ("[{0}] Enable Drain Mode for Session Host" -f $virtualMachine.Name)
                        Update-AzWvdSessionHost -Name $virtualMachine.SessionHost.Name.Split("/")[-1] -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -AllowNewSession:$false | Out-Null

                        $userSessions = Get-AzWvdUserSession -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -SessionHostName $virtualMachine.sessionHost.Name.Split("/")[-1] | Where-Object { $_.SessionState -ne "Disconnected" }
                        If ($userSessions) {
                            Write-Verbose ("[{0}] Sending logoff messages to ACTIVE logged on users" -f $virtualMachine.Name)
                            Foreach ($session in $userSessions) {
                                Write-Progress -ParentId 42 -Activity ("Sending Logoff Messages") -Status ("Sessions: {0}" -f $userSessions.Where{ $_.SessionState -ne "Disconnected" }.Count)
                                Send-AzWvdUserSessionMessage `
                                    -SessionHostName $virtualMachine.sessionHost.Name.Split("/")[-1] `
                                    -ResourceGroupName $ResourceGroupName `
                                    -HostPoolName $HostPoolName `
                                    -MessageTitle "!! WARNING - SYSTEM MAINTENANCE !!" `
                                    -MessageBody $Global:LogOffMessage `
                                    -UserSessionId $session.Name.Split("/")[-1]
                                $msgsSent++
                            }
                            Write-Progress -ParentId 42 -Activity ("Sending Logoff Messages") -Completed
                        }
                    }
                    Else { Write-Warning ("[{0}] Virtual Machine does not have a Session Host object" -f $virtualMachine.Name) }
                    
                    $x++
                    $logEntry = [PSCustomObject]@{
                        Timestamp         = [DateTime]::UtcNow.ToString('o')
                        CorrelationId     = $correlationId
                        Computer          = $env:COMPUTERNAME
                        UserName          = $azContext.Account.Id
                        EntryType         = "INFO"
                        Subscription      = $azContext.Subscription.Name
                        ResourceGroupName = $ResourceGroupName
                        HostPoolName      = $HostPoolName
                        SessionHostGroup  = $SessionHostGroup.ToUpper()
                        SessionHostName   = $virtualMachine.SessionHost.Name.Split("/")[-1]
                        AllowNewSessions  = "False"
                        'WVD-Maintenance' = "True"
                    }
                    New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_Maintenance_CL" -logMessage $logEntry -Verbose:$false
                }
                Write-Progress -Id 42 -Activity ("[{0}] Updating Maintenance Tag and Drain Mode" -f $HostPoolName) -Completed

                # 5 minute sleep timer to allow active users to save work and logoff - update these values to change the duration
                If ($msgsSent -gt 0) {
                    For ($i = 0; $i -lt 300; $i++) {
                        Write-Progress -Activity "WVD Session Logoff Stall Timer" -Status "Please wait..." -SecondsRemaining (300 - $i)
                        Start-Sleep -Milliseconds 999
                    }
                    Write-Progress -Activity "WVD Session Logoff Stall Timer" -Completed
                }
                Else { Show-Menu -Title ("No Active Sessions found") -Style Info -DisplayOnly -Color Green }

                # collects the number of running vm(s) to determine which to stop
                $vmsOnline = ($vmCollection.Where{ $_.PowerState -eq "VM running" } | Measure-Object).Count

                If ($vmsOnline -gt 0) {
                    # prevent this prompt by using -Confirm $false
                    If ($PSCmdlet.ShouldProcess(("{0} Running WVD Session Hosts" -f $vmsOnline), ("STOP and DEALLOCATE Virtual Machines in Group {0}" -f $SessionHostGroup.ToUpper()))) {
                    
                        # loop through each running vm and initiate the stop command without waiting - no need to wait as the portal should be used to validate the vm state
                        Write-Host ("`n`r")
                        $vmCollection.Where{ $_.PowerState -eq "VM running" } | Foreach-Object {
                            $shName = $_.SessionHost.Name
                            $_ | Stop-AzVm -NoWait -Force | Select-Object @{l = "Session Host Name"; e = { $shName } }, @{l = "Group"; e = { $SessionHostGroup } }, @{l = "Stop VM Status"; e = { $_.IsSuccessStatusCode } }
                        } | Format-Table -Autosize
                    
                        Write-Host ("-" * 120) -ForegroundColor Green
                        Write-Host ("-- Attempted to STOP and DEALLOCATE {0} virtual machines. Please verify state for each VM in the Azure Portal." -f $vmsOnline) -ForegroundColor Green
                        Write-Host ("-" * 120) -ForegroundColor Green
                    }
                    Else { Write-Warning "User aborted Stop-AzVM operation!" }
                }
                Else { Write-Warning ("Unable to find any Virtual Machines in a 'running' state") }
            }
            Else { Write-Warning "User aborted WVD Maintenance operation!" }
        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
    }
}