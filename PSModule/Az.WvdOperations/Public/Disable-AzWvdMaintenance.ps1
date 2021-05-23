Function Disable-AzWvdMaintanence {
    <#
        .SYNOPSIS
            Puts a specific group of session hosts in a host pool into 'production'
        .DESCRIPTION
            This function targets a specific host pool and group of session hosts, changes their Azure maintenance tag to TRUE and turns on drain mode to prevent new connections. Use of this function is for session host redeployment for monthly patching or session host recycling.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
    Param (
        # Name of the Resource Group of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory = $true, Position = 0)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$ResourceGroupName,

        # Name of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory = $true, Position = 1)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.DesktopVirtualization/hostpools", "ResourceGroupName")]
        [System.String]$HostPoolName,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$LogAnalyticsResourceGroup,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.OperationalInsights/workspaces", "DeploymentResourceGroup")]
        [System.String]$LogAnalyticsWorkspace,

        # Group of Session Hosts to target (A or B)
        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateSet("A", "B", "ALL")]
        [String]$SessionHostGroup
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
            # collection the virtual machines based on WVD-Group tag
            Write-Verbose ("[{0}] Gathering Virtual Machine data (Group: {1})" -f $ResourceGroupName, $SessionHostGroup.ToUpper())
            [System.Collections.Generic.List[System.Object]]$vmCollection = @()
            If ($SessionHostGroup -eq "ALL") { Get-AzVM -ResourceGroupName $ResourceGroupName -Status | ForEach-Object { $vmCollection.Add($_) | Out-Null } }
            Else { Get-AzVM -ResourceGroupName $ResourceGroupName -Status | Where-Object { $_.Tags["WVD-Group"] -eq $SessionHostGroup } | ForEach-Object { $vmCollection.Add($_) | Out-Null } }
            
            # loop through the virtual machines and add the session host information to the vm object
            $i = 0
            $sessionHostCount = 0
            Write-Verbose ("[{0}] Gathering Session Host data (Group: {1})" -f $HostPoolName, $SessionHostGroup.ToUpper())
            Foreach ($virtualMachine in $vmCollection) {
                Write-Progress -Activity ("[{0}] Gathering Session Host data (Group: {1})" -f $HostPoolName, $SessionHostGroup.ToUpper()) -Status ("Session Hosts Collected: {0}" -f $sessionHostCount) -CurrentOperation $virtualMachine.Name -PercentComplete (($i / $vmCollection.Count) * 100)
                # collect WVD session host objects
                $sessionHost = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName | Where-Object { $_.ResourceId -eq $virtualMachine.Id }
                # collect extension object data
                If ((Get-AzVMExtension -ResourceGroupName $virtualMachine.ResourceGroupName -VMName $virtualMachine.Name).Where{ $_.Publisher -eq "Microsoft.Powershell" -and $_.ExtensionType -eq "DSC" }) {
                    $extensionStatus = Get-AzVMDscExtensionStatus -VMName $virtualMachine.Name -ResourceGroupName $virtualMachine.ResourceGroupName -ErrorAction SilentlyContinue
                }
                Else {
                    $extensionStatus = [PSCustomObject]@{StatusCode = "ProvisioningState/missing" }
                }
                
                If ($sessionHost) {
                    $sessionHostCount++
                    $virtualMachine | Add-Member -NotePropertyName SessionHost -NotePropertyValue $sessionHost
                    $virtualMachine | Add-Member -NotePropertyName ExtensionStatus -NotePropertyValue $extensionStatus
                    $virtualMachine | Add-Member -NotePropertyName Updated -NotePropertyValue $false
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

            If ($missingVMs) { $missingVMs | ForEach-Object { $vmCollection.Remove($_) | Out-Null } }
            Write-Progress -Activity ("[{0}] Gathering Session Hosts from Group {1}" -f $HostPoolName, $SessionHostGroup.ToUpper()) -Completed
            
            If ($vmCollection.Count -eq 0) { Write-Warning "No Session Hosts found enabled for maintenance!" }
            Else {
                $vmMaintenanceHash = $vmCollection | Group-Object -Property { $_.Tags["WVD-Maintenance"] } -AsHashTable -AsString
                # prevent this prompt by using -Confirm $false
                If ($PSCmdlet.ShouldProcess(("{0} WVD Session Hosts" -f $vmMaintenanceHash["True"].Count), "DISABLE maintenace")) {
                    # loop through each vm in the collection, update the maintenance/dsc tag and turn off drain mode
                    If ($SessionHostGroup -eq "ALL") {
                        Write-Verbose ("[{0}] Updating Host Pool 'WVD-Maintenance' Tag" -f $HostPoolName)
                        $HostPool = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName
                        Update-AzTag -ResourceId $HostPool.Id -Tag @{"WVD-Maintenance" = $false} -Operation Merge | Out-Null
                        $logEntry = [PSCustomObject]@{
                            Timestamp             = [DateTime]::UtcNow.ToString('o')
                            CorrelationId         = $correlationId
                            Computer              = $env:COMPUTERNAME
                            UserName              = $azContext.Account.Id
                            EntryType             = "INFO"
                            Subscription          = $azContext.Subscription.Name
                            ResourceGroupName     = $ResourceGroupName
                            HostPoolName          = $HostPoolName
                            SessionHostGroup      = $SessionHostGroup.ToUpper()
                            SessionHostName       = [System.String]::Empty
                            'WVD-Maintenance'     = 'False'
                        }
                        New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_Maintenance_CL" -logMessage $logEntry -Verbose:$false
                    }

                    $x = 0
                    Foreach ($virtualMachine in $vmMaintenanceHash["True"]) {
                        Write-Verbose ("[{0}] Checking Session Host DSC Extension" -f $virtualMachine.Name)
                        Write-Progress -Id 42 -Activity ("[{0}] Updating Maintenance Tag" -f $HostPoolName) -Status ("Session Hosts Updated: {0}" -f $x) -CurrentOperation $virtualMachine.SessionHost.Name -PercentComplete (($x / $vmCollection.Count) * 100)
                        
                        Update-AzTag -ResourceId $virtualMachine.Id -Tag @{"WVD-Maintenance" = $false} -Operation Merge | Out-Null
                        $virtualMachine.Updated = $true
                        $x++
                        $logEntry = [PSCustomObject]@{
                            Timestamp             = [DateTime]::UtcNow.ToString('o')
                            CorrelationId         = $correlationId
                            Computer              = $env:COMPUTERNAME
                            UserName              = $azContext.Account.Id
                            EntryType             = "INFO"
                            Subscription          = $azContext.Subscription.Name
                            ResourceGroupName     = $ResourceGroupName
                            HostPoolName          = $HostPoolName
                            SessionHostGroup      = $SessionHostGroup.ToUpper()
                            SessionHostName       = $virtualMachine.SessionHost.Name.Split("/")[-1]
                            'WVD-Maintenance'     = "False"
                        }
                        New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_Maintenance_CL" -logMessage $logEntry -Verbose:$false
                    }
                    Write-Progress -Id 42 -Activity ("[{0}] Updating Maintenance and DSC Tag" -f $HostPoolName) -Completed
                }
                Else { Write-Warning "User aborted WVD Maintenance operation!" }
            }
        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
    }
}