Function Remove-AzWvdResources {
    <#
        .SYNOPSIS
            Removes session hosts from host pools and deletes Azure resources
        .DESCRIPTION
            This function is used after session hosts have been put into 'maintenance'. This will remove session hosts from host pools and delete the virtual machine. Optionally, you can delete the attached NIC(s) and Disk(s).
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

        # Group of Session Hosts to target (A or B)
        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateSet("A", "B", "ALL")]
        [String]$SessionHostGroup,

        # Also removes nic(s) and disk(s)
        [Switch]$IncludeAttachedResources
    )
    BEGIN {
        Function _CheckDeletionStatus {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
                [object]$objectDeletionURI,
                [Parameter(Mandatory = $true, Position = 1)]
                [string]$azAccessToken

            )
            BEGIN {
                $objectDeletionCounter = [PSCustomObject]@{
                    Succeeded  = 0
                    Failed     = [System.Collections.Generic.List[System.Object]]@()
                    InProgress = 0
                    Unknown    = 0
                }
            }
            PROCESS {
                try { $objectDeletionContent = ((Invoke-WebRequest -Method Get -Headers @{"Authorization" = "Bearer " + $azAccessToken } -Uri $objectDeletionURI -Verbose:$false).Content | ConvertFrom-Json) }
                catch {
                    [System.Console]::ForegroundColor = "Red"
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.SystemException]::new("Failed to get virtual machine deletion status"),
                        "ObjectDeletionStatus",
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $objectDeletionURI
                    )
                    [System.Console]::ResetColor()
                }
                
                Switch ($objectDeletionContent.Status) {
                    "Succeeded" { $objectDeletionCounter.Succeeded++ }
                    "Cancelled" {
                        $objectDeletionCounter.Failed.Add($objectDeletionURI)
                        [System.Console]::ForegroundColor = "Red"
                        [System.Management.Automation.ErrorRecord]::new(
                            [System.SystemException]::new("Virtual machine deletion cancelled"),
                            "ObjectDeletionCancelled",
                            [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                            $objectDeletionURI
                        )
                        [System.Console]::ResetColor()
                    }
                    "Failed" {
                        $objectDeletionCounter.Failed.Add($objectDeletionURI)
                        [System.Console]::ForegroundColor = "Red"
                        [System.Management.Automation.ErrorRecord]::new(
                            [System.SystemException]::new("Virtual machine deletion failed"),
                            "ObjectDeletionFailed",
                            [System.Management.Automation.ErrorCategory]::OperationStopped,
                            $objectDeletionURI
                        )
                        [System.Console]::ResetColor()
                    }
                    "InProgress" { $objectDeletionCounter.InProgress++ }
                    Default { 
                        $objectDeletionCounter.Unknown++ 
                        Write-Warning $objectDeletionContent.Status
                    }
                }
                Start-Sleep -Milliseconds 999
            }
            END {
                return $objectDeletionCounter
            }
        }
    }
    PROCESS {
        try {
            # collection the virtual machines based on WVD-Group tag
            If ($SessionHostGroup -eq "ALL") { $vmCollection = Get-AzVM -ResourceGroupName $ResourceGroupName -Status }
            Else { $vmCollection = Get-AzVM -ResourceGroupName $ResourceGroupName -Status | Where-Object { $_.Tags["WVD-Group"] -eq $SessionHostGroup } }
            
            # loop through the virtual machines and add the session host information to the vm object
            $i = 0
            $sessionHostCount = 0
            Write-Verbose ("Creating Virtual Machine Collection Object")
            Foreach ($virtualMachine in $vmCollection) {
                Write-Progress -Activity ("[{0}] Gathering Session Hosts from Group {1}" -f $HostPoolName, $SessionHostGroup.ToUpper()) -Status ("Virtual Machines Collected: {0}" -f $i) -CurrentOperation $virtualMachine.Name -PercentComplete (($i / $vmCollection.Count) * 100)
                $sessionHost = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName | Where-Object { $_.ResourceId -eq $virtualMachine.Id }
                
                If ($sessionHost) {
                    $sessionHostCount++
                    $virtualMachine | Add-Member -NotePropertyName SessionHost -NotePropertyValue $sessionHost
                }
                $i++
            }
            Write-Progress -Activity ("[{0}] Gathering Session Hosts from Group {1}" -f $HostPoolName, $SessionHostGroup.ToUpper()) -Completed

            # separate messages based on removing attached resources
            If ($IncludeAttachedResources) { $message = ("REMOVE and DELETE Session Host(s) and attached resources (VM, OsDisk, Nic)" -f $HostPoolName) }
            Else { $message = ("REMOVE and DELETE Session Host(s) (VM ONLY)" -f $HostPoolName) }

            # prevent this prompt by using -Confirm $false
            If ($PSCmdlet.ShouldProcess(("{0} WVD Session Host(s)" -f $vmCollection.Count), $message)) {
                # loop through each vm in the collection, remove from host pool, delete the vm, and optionally delete the nic and os disk
                $i = 1
                $accessToken = Get-AzureAccessToken
                [System.Collections.Generic.List[System.Object]]$attachedResources = @()
                [System.Collections.Generic.List[System.Object]]$attachedResourcesDeletionURIs = @()
                [System.Collections.Generic.List[System.Object]]$vmDeletionURIs = @()
                Write-Verbose ("Attempting to delete Azure Virutal Machines")
                Foreach ($virtualMachine in $vmCollection) {
                    Write-Progress -Activity "Windows Virtual Desktop - Azure Resource Clean Up" -Status ("Virtual Machine: {0} ({1} of {2})" -f $virtualMachine.Name, $i, $vmCollection.Count) -CurrentOperation ("Removing Session Host from Host Pool") -PercentComplete (($i / $vmCollection.Count) * 100)
                    If ($virtualMachine.SessionHost) {
                        Write-Verbose ("[{0}] Removing Session Host object from Host Pool" -f $virtualMachine.SessionHost.Name.Split("/")[-1])
                        Remove-AzWvdSessionHost -Name $virtualMachine.SessionHost.Name.Split("/")[-1] -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -Force | Out-Null
                    }
                    Else { Write-Warning ("[{0}] Virtual Machine does not have a Session Host object" -f $virtualMachine.Name) }

                    $virtualMachine.NetworkProfile.NetworkInterfaces | ForEach-Object { $attachedResources.Add($_.Id) }
                    $attachedResources.Add( $virtualMachine.StorageProfile.OsDisk.ManagedDisk.Id )      
                    
                    try {
                        Write-Progress -Activity "Windows Virtual Desktop - Azure Resource Clean Up" -Status ("Virtual Machine: {0} ({1} of {2})" -f $virtualMachine.Name, $i, $vmCollection.Count) -CurrentOperation ("Removing Virutal Machine") -PercentComplete (($i / $vmCollection.Count) * 100)
                        $vmDeletion = Invoke-WebRequest -Method Delete -Headers @{"Authorization" = "Bearer " + $accessToken } -Uri ("https://management.azure.com{0}?api-version=2020-06-01" -f $virtualMachine.Id) -Verbose:$false
                        $vmDeletionURIs.Add(($vmDeletion.RawContent.Split("`n") | Select-String -Pattern "Azure-AsyncOperation").Line.split(" ")[-1])
                    }
                    catch {
                        [System.Console]::ForegroundColor = "Red"
                        [System.Management.Automation.ErrorRecord]::new(
                            [System.SystemException]::new("Failed to delete virtual machine"),
                            "VMDeletionFailed",
                            [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                            $virtualMachine.Name
                        )
                        [System.Console]::ResetColor()
                    }
                    Start-Sleep -Milliseconds 500
                    $i++
                }

                Write-Verbose ("Validating the Virutal Machine delete status")
                while ($true) {
                    $deletionResults = $vmDeletionURIs | _CheckDeletionStatus -azAccessToken $accessToken
                    Write-Progress -Activity "Windows Virtual Desktop - Validate Azure Resource Deletion" -Status ("Virutal Machine: ({0} of {1})" -f $deletionResults.Succeeded, $vmDeletionURIs.Count) -CurrentOperation ("Waiting on deletion of Azure Virtual Machine(s)") -PercentComplete (($deletionResults.Succeeded / $vmDeletionURIs.Count) * 100)
                    If ($deletionResults.Failed.Count -gt 0) { $deletionResults.Failed | ForEach-Object { $vmDeletionURIs.Remove($_) | Out-Null } }
                    If ($deletionResults.Succeeded -eq $vmDeletionURIs.Count) { break }
                    Start-Sleep -Seconds 10
                }
                Write-Progress -Activity "Windows Virtual Desktop - Validate Azure Resource Deletion" -Completed
                $deletionResults = $null

                If ($IncludeAttachedResources) {
                    $x = 1
                    Write-Verbose ("Attempting to delete Azure Resources assigned to Virtual Machines")
                    foreach ($attachedResource in $attachedResources) {
                        try {
                            Write-Progress -Activity "Windows Virtual Desktop - Azure Resource Clean Up" -Status ("Attached Resource: ({0} of {1})" -f $x, $attachedResources.Count) -CurrentOperation ("Deleting Azure Disk(s) and Virtual Network Interface(s)") -PercentComplete (($x / $attachedResources.Count) * 100)
                            $attachedResourceDeletion = Invoke-WebRequest -Method Delete -Headers @{"Authorization" = "Bearer " + $accessToken } -Uri ("https://management.azure.com{0}?api-version=2019-07-01" -f $attachedResource) -Verbose:$false
                            $attachedResourcesDeletionURIs.Add( ($attachedResourceDeletion.RawContent.Split("`n") | Select-String -Pattern "Azure-AsyncOperation").Line.split(" ")[-1] )
                            Start-Sleep -Milliseconds 500
                        }
                        catch {
                            [System.Console]::ForegroundColor = "Red"
                            [System.Management.Automation.ErrorRecord]::new(
                                [System.SystemException]::new("Failed to delete virtual machine attached object"),
                                "VMAttachedObjectDeletionFailed",
                                [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                                $attachedResource
                            )
                            [System.Console]::ResetColor()
                        }
                        $x++
                    }

                    Write-Verbose ("Validating deletion of Azure Resources")
                    while ($true) {
                        $deletionResults = $attachedResourcesDeletionURIs | _CheckDeletionStatus -azAccessToken $accessToken
                        Write-Progress -Id 42 -Activity "Windows Virtual Desktop - Validate Azure Resource Deletion" -Status ("Attached Resource: ({0} of {1})" -f $deletionResults.Succeeded, $attachedResourcesDeletionURIs.Count) -CurrentOperation ("Waiting on deletion of Azure Disk(s) and Virtual Network Interface(s)") -PercentComplete (($deletionResults.Succeeded / $attachedResourcesDeletionURIs.Count) * 100)
                        If ($deletionResults.Failed.Count -gt 0) { $deletionResults.Failed | ForEach-Object { $attachedResourcesDeletionURIs.Remove($_) | Out-Null } }
                        If ($deletionResults.Succeeded -eq $attachedResourcesDeletionURIs.Count) { break }
                        Start-Sleep -Milliseconds 500
                    }
                    Write-Progress -Activity "Completed"  -Completed
                    Write-Host ("`n`r")
                    Write-Host ("-" * 120) -ForegroundColor Green
                    Write-Host ("-- DELETED {0} WVD Virtual Machines and {1} Attached Resources. Please validate using PowerShell or Azure Portal." -f $vmCollection.Count, $attachedResources.Count) -ForegroundColor Green
                    Write-Host ("-" * 120) -ForegroundColor Green
                }
                Else {
                    Write-Host ("`n`r")
                    Write-Host ("-" * 120) -ForegroundColor Green
                    Write-Host ("-- DELETED {0} WVD Virtual Machines. Attached resources were SKIPPED. Please validate using PowerShell or Azure Portal." -f $vmCollection.Count, $attachedResources.Count) -ForegroundColor Green
                    Write-Host ("-" * 120) -ForegroundColor Green
                }
            }
            Else { Write-Warning "User aborted clean up operation!" }

        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
    }
}