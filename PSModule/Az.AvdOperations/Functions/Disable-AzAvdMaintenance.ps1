Function Disable-AzAvdMaintanence {
    <#
        .SYNOPSIS
            Removes Azure Virtual Desktop Session Hosts from 'maintenance'
        .DESCRIPTION
            This function targets a specific host pool and group of session hosts, changes their Azure maintenance tag to FALSE and turns OFF drain mode to allow new connections. Use this cmdlet to ensure Session Hosts are being properly managed by the AutoScale system.
        .EXAMPLE
            Disable-AzAvdMaintenance -ResourceGroupName POOL-RG-1 -HostPoolName hostpool-01

            The above command will target a specific Host Pool in a ResourceGroup and will change the 'WVD-Maintenance' Azure Tag to 'False' for all AVD resources.
        .EXAMPLE
            Disable-AzAvdMaintenance -ResourceGroupName POOL-RG-1 -HostPoolName hostpool-01 -ResourceType SessionHostsOnly

            The above command will target a specific Host Pool in a ResourceGroup and will change the 'WVD-Maintenance' Azure Tag to 'False' for Session Hosts Only.
        .EXAMPLE
            Disable-AzAvdMaintenance -ResourceGroupName POOL-RG-1 -HostPoolName hostpool-01 -Force

            The above command will target a specific Host Pool in a ResourceGroup and will change the 'WVD-Maintenance' Azure Tag to 'False' for all AVD resources. The Force switch will set the tag to false regardless of current state.
        .EXAMPLE
            Disable-AzAvdMaintenance -ResourceGroupName POOL-RG-1 -HostPoolName hostpool-01 -Confirm:$false

            The above command will target a specific Host Pool in a ResourceGroup and will change the 'WVD-Maintenance' Azure Tag to 'False' for all AVD resources. The -Confirm parameter will bypass any confirmation prompts.
    #>
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
    Param (
        # Name of the Resource Group containing the Azure Virtual Desktop HostPool (supports tab completion)
        [Parameter(Mandatory=$true,Position=0)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$ResourceGroupName,

        # Azure Virtual Desktop HostPool Name (supports tab completion)
        [Parameter(Mandatory=$true,Position=1)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.DesktopVirtualization/hostpools","ResourceGroupName")]
        [System.String]$HostPoolName,

        # Optionally select to only disable Azure Maintenance tag on Session Hosts vs All resources
        [ValidateSet("All","SessionHostsOnly")]
        [System.String]$ResourceType = "All",

        # Bypasses all confirmation prompts
        [Parameter(Mandatory=$false)]
        [Switch]$Force
    )
    BEGIN {
        #Requires -Modules Az.Accounts,Az.DesktopVirtualization
        Get-AzAuthentication
        Write-Verbose ("[Azure Authentication] {0} Connected to {1} ({2})" -f $SCRIPT:AzAuthentication.Account.Id,$SCRIPT:AzAuthentication.Subscription.Name,$SCRIPT:AzAuthentication.Subscription.Id)
    }
    PROCESS {
        try {
            # collection the virtual machines based on WVD-Group tag
            Write-Verbose ("[{0}] Gathering Virtual Machine data" -f $ResourceGroupName)
            [System.Collections.Generic.List[System.Object]]$vmCollection = @()
            Get-AzVM -ResourceGroupName $ResourceGroupName -Status | ForEach-Object { $vmCollection.Add($_) | Out-Null }
            
            # loop through the virtual machines and add the session host information to the vm object
            $i = 0
            $sessionHostCount = 0
            Write-Verbose ("[{0}] Gathering Session Host data" -f $HostPoolName)
            Foreach ($virtualMachine in $vmCollection) {
                Write-Progress -Activity ("[{0}] Gathering Session Host data" -f $HostPoolName) -Status ("Session Hosts Collected: {0}" -f $sessionHostCount) -CurrentOperation $virtualMachine.Name -PercentComplete (($i / $vmCollection.Count) * 100)
                # collect WVD session host objects
                $sessionHost = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName | Where-Object {$_.ResourceId -eq $virtualMachine.Id}
                
                If ($sessionHost) {
                    $sessionHostCount++
                    $virtualMachine | Add-Member -NotePropertyName SessionHost -NotePropertyValue $sessionHost
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
            Write-Progress -Activity ("[{0}] Gathering Session Hosts" -f $HostPoolName) -Completed

            $vmMaintenanceHash = $vmCollection | Group-Object -Property {$_.Tags["WVD-Maintenance"]} -AsHashTable -AsString
            If ($Force) { $shCollection = $vmCollection }
            Else { $shCollection = $vmMaintenanceHash["True"] }

            If ($shCollection.Count -eq 0) { Write-Warning "No Session Hosts found!" }
            Else {
                # prevent this prompt by using -Confirm $false
                If ($PSCmdlet.ShouldProcess(("{0} WVD Session Hosts" -f $shCollection.Count),"DISABLE maintenace")) {
                    # loop through each vm in the collection, update the maintenance/dsc tag and turn off drain mode
                    
                    $hpTagUpdated = $false
                    If ($ResourceType -eq "All") {
                        Write-Verbose ("[{0}] Updating Host Pool 'WVD-Maintenance' Tag" -f $HostPoolName)
                        $HostPool = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName
                        try {
                            Update-AzTag -ResourceId $HostPool.Id -Tag @{"WVD-Maintenance" = $false} -Operation Merge | Out-Null
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
                            $tagUpdate = @{"WVD-Maintenance" = $false}
                            Update-AzTag -ResourceId $virtualMachine.Id -Tag $tagUpdate -Operation Merge | Out-Null
                            Update-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -Name $virtualMachine.SessionHost.Name.Split("/")[-1] -AllowNewSession:$true | Out-Null
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
            }
            Return $results
        }
    }
}