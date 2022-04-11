Function Remove-AzAvdResources {
    <#
        .SYNOPSIS
            Removes session hosts from host pools and deletes Azure resources
        .DESCRIPTION
            This cmdlet is used to delete Azure Virtual Desktop resources. The default operation will remove the Session Hosts from their Host Pool, delete the Virtual Machines and their attached resources (OS Disk and Network Interface).
    #>
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
    Param (
        # Name of the Resource Group where the Azure Virtual Desktop Host Pool is located. (supports tab completion)
        [Parameter(Mandatory=$true,Position=0)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$ResourceGroupName,

        # Name of the Azure Virtual Desktop Host Pool. (supports tab completion)
        [Parameter(Mandatory=$true,Position=1)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.DesktopVirtualization/hostpools","ResourceGroupName")]
        [System.String]$HostPoolName,

        # Switch parameter when used will attempt to delete the Host Pool, Desktop Application Group, Virutal Machines and their attached resources (OS Disk and Network Interface).
        [Parameter(Mandatory=$false)]
        [Switch]$All,

        # Switch parameter that bypasses any confirmation prompts.
        [Parameter(Mandatory=$false)]
        [Switch]$Force
    )
    BEGIN {
        #Requires -Module Az.DesktopVirtualization, Az.Accounts
        Get-AzAuthentication
        Write-Verbose ("[Azure Authentication] {0} Connected to {1} ({2})" -f $SCRIPT:AzAuthentication.Account.Id,$SCRIPT:AzAuthentication.Subscription.Name,$SCRIPT:AzAuthentication.Subscription.Id)
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            $hostPool = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -ErrorAction SilentlyContinue
            If (-NOT $hostPool) {
                Write-Verbose ("Azure Virtual Desktop HostPool not found!")
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::New(
                        [System.SystemException]::New(("HostPool ({0}) not found in {1}" -f $HostPoolName, $ResourceGroupName)),
                        "HostPoolNotFoundInResourceGroup",
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        ($HostPoolName)
                    )
                )
            }
            
            Write-Verbose ("Azure Virtual Desktop HostPool found!")
            # $avdContext = Get-AzContext
            # $azManagementUri = (Get-AzEnvironment -Name $avdContext.Environment.Name).ResourceManagerUrl
            # Write-Verbose ("Saved Azure Context to {0} as {1} ({2})" -f $avdContext.Subscription.Name,$avdContext.Account.Id,$avdContext.Environment.Name)
            Write-Verbose ("Azure Management Uri: {0}" -f $SCRIPT:AzAuthentication.Environment.ResourceManagerUrl)
        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }

        Function _CheckDeletionStatus {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
                [object]$objectDeletionURI,
                [Parameter(Mandatory=$true,Position=1)]
                [string]$azAccessToken

            )
            BEGIN {
                $statusTracker = [PSCustomObject]@{
                    Succeeded = 0
                    Failed = [System.Collections.Generic.List[Object]]@()
                    InProgress = 0
                    Unknown = 0
                }
            }
            PROCESS {
                try { $objectDeletionContent = ((Invoke-WebRequest -Method Get -Headers @{"Authorization" = "Bearer " + $azAccessToken} -Uri $objectDeletionURI -Verbose:$false).Content | ConvertFrom-Json) }
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
                    "Succeeded" { $statusTracker.Succeeded++ }
                    "Cancelled" {
                        $statusTracker.Failed.Add($objectDeletionURI)
                        [System.Console]::ForegroundColor = "Red"
                        [System.Management.Automation.ErrorRecord]::new(
                            [System.SystemException]::new("Azure Resource deletion cancelled"),
                            "ObjectDeletionCancelled",
                            [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                            $objectDeletionURI
                        )
                        [System.Console]::ResetColor()
                    }
                    "Failed" {
                        $statusTracker.Failed.Add($objectDeletionURI)
                        [System.Console]::ForegroundColor = "Red"
                        [System.Management.Automation.ErrorRecord]::new(
                            [System.SystemException]::new("Azure Resource deletion failed"),
                            "ObjectDeletionFailed",
                            [System.Management.Automation.ErrorCategory]::OperationStopped,
                            $objectDeletionURI
                        )
                        [System.Console]::ResetColor()
                    }
                    "InProgress" { $statusTracker.InProgress++ }
                    Default { 
                        $statusTracker.Unknown++ 
                        Write-Warning $objectDeletionContent.Status
                    }
                }
                Start-Sleep -Milliseconds 999
            }
            END {
                return $statusTracker
            }
        }

        Function _GetRestApiRmUri {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
                [System.Object]$ResourceId,

                [Parameter(Mandatory=$true)]
                [System.String]$ResourceType,

                [Parameter(Mandatory=$true)]
                [string]$azAccessToken
            )
            BEGIN {
                $baseUri = ($SCRIPT:AzAuthentication.Environment.ResourceManagerUrl).TrimEnd("/")
                [System.Collections.Generic.List[Object]]$resCollection = @()
                $namespace = $ResourceType.Split('/')[0]
                $type = $ResourceType.Split('/')[1]
                $apiVersion = ((Get-AzResourceProvider -ProviderNamespace $namespace -Debug:$false).ResourceTypes | Where-Object {$_.ResourceTypeName -eq $type} | Select-Object -ExpandProperty ApiVersions)[0]
                Write-debug "begin"
            }
            PROCESS {
                Write-Progress -ParentId 0 -Id 50 -Activity ("Creating Resource URI with latest API Version") -Status ("Resource: {0}" -f $ResourceId) -CurrentOperation ("URI(s) Collected: {0}" -f $resCollection.Count)
                $ResourceId = $ResourceId.TrimStart('/')
                $resourceUri = ("{0}/{1}?api-version={2}" -f$baseUri,$ResourceId,$apiVersion)

                Switch ($ResourceType) {
                    'Microsoft.DesktopVirtualization/applicationgroups' { $Priority = 0 }
                    'Microsoft.DesktopVirtualization/hostpools' { $Priority = 1 }
                    'Microsoft.Compute/virtualMachines' { $Priority = 2 }
                    'Microsoft.Compute/disks' { $Priority = 3 }
                    'Microsoft.Network/networkInterfaces' { $Priority = 4 }
                    Default { $Priority = 9 }
                }

                $objResource = [PSCustomObject]@{
                    Priority = $Priority
                    ResourceType = $ResourceType
                    ResourceUri = $resourceUri
                }
                $resCollection.Add($objResource)
                Write-Debug "process"
            }
            END {
                Write-debug "end"
                Write-Progress -Id 50 -Activity "Completed" -Completed
                Return $resCollection
            }
        }

        Function _DeleteAvdResources {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
                [System.Object[]]$ResourceUri,
                [Parameter(Mandatory=$true,Position=1)]
                [System.String]$azAccessToken
            )
            BEGIN {
                [System.Collections.Generic.List[Object]]$deletionUris = @()
                $objectDeletionResults = [PSCustomObject]@{
                    Succeeded = 0
                    Failed = 0
                }
                $i = 0
            }
            PROCESS {
                try {
                    Write-debug "start"
                    If ($ResourceUri.ResourceType -in ('Microsoft.DesktopVirtualization/hostpools','Microsoft.Compute/virtualMachines','Microsoft.DesktopVirtualization/applicationgroups')) {
                        $deleteStage = 1
                        $Types = "Desktop Application Group, HostPool, and Virtual Machines"
                    }
                    ElseIf ($ResourceUri.ResourceType -in ('Microsoft.Compute/disks','Microsoft.Network/networkInterfaces')) {
                        $deleteStage = 2
                        $Types = "OS Disks and Network Interfaces"
                    }
                    Write-Progress -Id 7 -Activity ("[STAGE: {0}] Attempting to DELETE {1}" -f $deleteStage,$Types) -Status ("Succeeded: {0}  |  Failed: {1}  |  Total: {2}" -f $objectDeletionResults.Succeeded, $objectDeletionResults.Failed, $i)  -CurrentOperation ("Working on: {0}" -f $ResourceUri.ResourceType)
                    
                    $result = Invoke-WebRequest -Method Delete -Uri $ResourceUri.ResourceUri -Headers @{Authorization = "Bearer " + $azAccessToken}
                    $statusCode = ($result.RawContent.Split("`n") | Select-String -Pattern "HTTP/1.1").Line.split(" ")[1]
                    If ($statusCode -eq "200") { $objectDeletionResults.Succeeded++ }
                    ElseIf ($statusCode -eq "202") {
                        $objectDeletionResults.Succeeded++
                        $deletionUris.Add(($result.RawContent.Split("`n") | Select-String -Pattern "Azure-AsyncOperation").Line.split(" ")[-1])
                    }
                    Else { $objectDeletionResults.Failed++ }
                    $i++
                }
                catch [System.Net.WebException]{
                    $errorDetails = ($_.ErrorDetails.Message | ConvertFrom-Json).Error
                    $errMessage = @"
----- ERROR DELETING AZURE RESOURCE -----
ResourceId: {0}
Code:       {1}
Message:    {2}

"@
                    Write-Host ($errMessage -f $ResourceUri,$errorDetails.Code,$errorDetails.Message) -ForegroundColor Red
                    Continue
                }
                catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
            }
            END {
                If ($deletionUris.Count -gt 0) {
                    Write-Progress -Id 7 -Activity ("[STAGE: {0}] Attempting to DELETE {1}" -f $deleteStage,$Types) -Status ("Succeeded: {0}  |  Failed: {1}  |  Total: {2}" -f $objectDeletionResults.Succeeded, $objectDeletionResults.Failed, $i)  -CurrentOperation ("Working on: {0}" -f $ResourceUri.ResourceType)
                    Write-Verbose ("Validating the Azure Resource delete status")
                    while ($true) {
                        $deletionResults = $deletionUris | _CheckDeletionStatus -azAccessToken $azAccessToken
                        Write-Progress -ParentId 7 -Id 14 -Activity "Validating Azure Resource Deletion" -Status ("Resource: ({0} of {1})" -f $deletionResults.Succeeded,$deletionUris.Count) -CurrentOperation ("Waiting on deletion of Azure Resource(s)") -PercentComplete (($deletionResults.Succeeded / $deletionUris.Count) * 100)
                        If($deletionResults.Failed -gt 0) { $deletionResults.Failed | ForEach-Object { $deletionUris.Remove($_) | Out-Null } }
                        If($deletionResults.Succeeded -eq $deletionUris.Count) { break }
                        Start-Sleep -Seconds 10
                    }
                    Write-Progress -Id 14 -Activity "Completed" -Completed
                }

                Return $objectDeletionResults
            }
        }

    }
    PROCESS {
        try {
            $altSubscription = $false
            $shCollection = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -ErrorAction SilentlyContinue
            If ($shCollection -AND $hostpool) {
                Write-Verbose ("Collecting Session Host data from HostPool: {0}" -f $HostPoolName)
                $hpSubscriptionId = $shCollection.Id.Split("/")[2] | ForEach-Object { $_ | Select-Object -Unique }
                $hpResourceGroup = $shCollection.Id.Split("/")[4] | ForEach-Object { $_ | Select-Object -Unique }
                $shSubscriptionId = $shCollection.ResourceId.Split("/")[2] | ForEach-Object { $_ | Select-Object -Unique }
                $shResourceGroup = $shCollection.ResourceId.Split("/")[4] | ForEach-Object { $_ | Select-Object -Unique }

                If ([System.String]::IsNullOrEmpty($shSubscriptionId) -OR [System.String]::IsNullOrEmpty($shResourceGroup)) {
                    Write-Warning ("Virtual Machine ResourceId has yet to register to Azure Virtual Desktop")
                    $PSCmdlet.ThrowTerminatingError(
                        [System.Management.Automation.ErrorRecord]::New(
                            [System.SystemException]::New(("Session Host ResourceId for Virtual Machine NULL or Empty")),
                            "VMResourceIdNullOrEmpty",
                            [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                            ("ResourceId")
                        )
                    )
                }
                ElseIf ($SCRIPT:AzAuthentication.Subscription.Id -ne $shSubscriptionId) {
                    Write-Warning ("Azure Virtual Desktop HostPool subscription does NOT match Session Host subscription!")
                    $altSubscription = $true
                    $azContext = Set-AzContext -SubscriptionId $shSubscriptionId
                    Write-Verbose ("Connected to: {0} using {1}" -f $azContext.Subscription.Name, $azContext.Account.Id)
                    Write-Verbose ("Collecting Session Host resources (Virtual Machines)")
                    $vmCollection = Get-AzVm -ResourceGroupName $shResourceGroup | Where-Object { $_.Id -in $shCollection.ResourceId }
                    Write-Verbose ("Found {0} Virtual Machine objects" -f $vmCollection.Count)
                    Set-AzContext -Context $SCRIPT:AzAuthentication | Out-Null
                    Write-Verbose ("Connected to: {0} using {1}" -f $SCRIPT:AzAuthentication.Subscription.Name, $SCRIPT:AzAuthentication.Account.Id)
                }
                Else {
                    Write-Verbose ("Collecting Session Host resources (Virtual Machines)")
                    $vmCollection = Get-AzVm -ResourceGroupName $shResourceGroup | Where-Object { $_.Id -in $shCollection.ResourceId }
                    Write-Verbose ("Found {0} Virtual Machine objects" -f $vmCollection.Count)
                }

                $vmCount = 0
                Foreach ($SessionHost in $shCollection) {
                    $vmIndex = $vmCollection.Id.IndexOf($SessionHost.ResourceId)
                    If ($vmIndex -ne -1) {
                        $vmCount++
                        $SessionHost | Add-Member -NotePropertyName VmProperties -NotePropertyValue $vmCollection[$vmIndex]
                        $SessionHost | Add-Member -NotePropertyName AlternateSubId -NotePropertyValue $altSubscription
                    }
                    Else {
                        $SessionHost | Add-Member -NotePropertyName VmProperties -NotePropertyValue $null
                    }
                }

                If ($shCollection.Count -ne $vmCount) { Write-Warning ("Some Virtual Machine(s) were not found - {0} of {1} collected!" -f $vmCount,$shCollection.Count) }

                $Done = Get-ChoicePrompt -Message (Show-Menu -Title "Azure Virtual Desktop Session Host Collection" -Menu ("`nDisplay results ({0} items)?" -f $shCollection.Count) -DisplayOnly -Style Info -Color Cyan) -OptionList "&Yes","&No","&Quit" -Default 0
                Switch ($Done) {
                    0 {
                        [System.Collections.Generic.List[Object]]$collectionOutput = @()
                        foreach ($SessionHost in $shCollection) {
                            $obj = [PSCustomObject]@{
                                Subscription = $hpSubscriptionId
                                ResourceGroup = $hpResourceGroup
                                HostPoolName = $HostPoolName
                                ApplicationGroup = ($hostpool.ApplicationGroupReference -Split '/')[-1]
                                SessionHost = $SessionHost.Name.Split('/')[-1]
                                VirtualMachine = $SessionHost.VmProperties.Name
                                DeployedInAlternateSubscription = $altSubscription
                                VmResourceId = $SessionHost.VmProperties.Id
                            }
                            $collectionOutput.Add($obj)
                        }
                        $collectionOutput | Out-GridView -Title "Azure Virtual Desktop Session Host Collection" -Wait
                    }
                    1 { Write-Warning ("Skipping Session Host Collection Output") }
                    2 { Return }
                }

                # separate messages based on removing hostpool and application group resources
                If ($All) {
                    $target = ("{0}, {1}, and {2} AVD Session Host(s)" -f $HostPoolName,($hostpool.ApplicationGroupReference -Split '/')[-1],$shCollection.Count)
                    $message = ("REMOVE and DELETE HostPool, ApplicationGroup, Session Host(s), and Virtual Machine(s)")
                }
                Else {
                    $target = ("{0} AVD Session Host(s)" -f $shCollection.Count)
                    $message = ("REMOVE and DELETE Session Host(s) and Virtual Machine(s)")
                }

                if ($PSCmdlet.ShouldProcess($target, $message)) {
                    $azAccessToken = Get-AzAccessToken
                    $i = 1
                    Foreach ($sessionHost in $shCollection) {
                        $name = $sessionHost.Name.Split("/")[-1]
                        Write-Progress -Activity "Azure Virtual Desktop - Session Host Clean Up" -Status ("Session Host: {0} ({1} of {2})" -f $Name,$i,$shCollection.Count) -CurrentOperation ("Removing Session Host from Host Pool") -PercentComplete (($i / $shCollection.Count) * 100)
                        Write-Verbose ("[{0}] Removing Session Host object from Host Pool ({1})" -f $Name, $HostPoolName)
                        Remove-AzWvdSessionHost -Name $Name -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -Force | Out-Null
                        $i++
                    }
                    Write-Progress -Activity "Completed" -Completed

                    If ($All) {
                        [System.Collections.Generic.List[Object]]$avdResourceUris = @()
                        
                        If ($hpResourceGroup -eq $ResourceGroupName -AND $shResourceGroup -eq $ResourceGroupName) {
                            $Types = ('Microsoft.DesktopVirtualization/hostpools','Microsoft.Compute/virtualMachines','Microsoft.Compute/disks','Microsoft.Network/networkInterfaces','Microsoft.DesktopVirtualization/applicationgroups')
                            $resHashTable = Get-AzResource -ResourceGroupName $ResourceGroupName | Where-Object {$_.ResourceType -in $Types} | Group-Object ResourceType -AsHashTable -AsString

                            $i = 0
                            Foreach ($ResourceType in $resHashTable.Keys) {
                                Write-Progress -Id 0 -Activity "Azure Virtual Desktop - Gather Resource URI(s)" -Status ("Resource Type: {0} ({1} of {2})" -f $ResourceType,($i + 1),$resHashTable.Keys.Count) -CurrentOperation ("Collecting URI(s) marked for deletion") -PercentComplete (($i / $resHashTable.Keys.Count) * 100)
                                $typeUris = $resHashTable[$ResourceType].ResourceId | _GetRestApiRmUri -ResourceType $ResourceType -azAccessToken $azAccessToken -Verbose
                                $typeUris | ForEach-Object {$avdResourceUris.Add($_)}
                                $i++
                            }
                            Write-Progress -Id 0 -Activity "Completed" -Completed
                        }
                        Else {
                            If (-NOT [System.String]::IsNullOrEmpty($hostpool.ApplicationGroupReference)) {
                                [System.String]$appGroupId = $hostpool.ApplicationGroupReference
                                $appGroupUri = _GetRestApiRmUri -ResourceId $appGroupId -ResourceType 'Microsoft.DesktopVirtualization/applicationgroups' -azAccessToken $azAccessToken
                                If ($appGroupUri) {
                                    Write-Verbose ("Created ResourceUri for Desktop Application Group ({0})" -f $hostpool.ApplicationGroupReference.Split('/')[-1])
                                    $avdResourceUris.Add($appGroupUri)
                                }
                                Else { Write-Warning ("Desktop Application Group Resource Uri could not be created!") }
                            }
                            Else { Write-Warning ("Desktop Application Group Resource Uri could not be created!") }

                            $hostPoolUri = _GetRestApiRmUri -ResourceId $hostpool.Id -ResourceType 'Microsoft.DesktopVirtualization/hostpools' -azAccessToken $azAccessToken
                            If ($hostPoolUri) {
                                Write-Verbose ("Created ResourceUri for HostPool ({0})" -f $HostPoolName)
                                $avdResourceUris.Add($hostPoolUri)
                            }
                            Else { Write-Warning ("HostPool Resource Uri could not be created!") }

                            $Types = ('Microsoft.DesktopVirtualization/hostpools','Microsoft.Compute/virtualMachines','Microsoft.Compute/disks','Microsoft.Network/networkInterfaces','Microsoft.DesktopVirtualization/applicationgroups')
                            If ($altSubscription) { $resHashTable = Get-AzResource -ResourceGroupName $shResourceGroup -DefaultProfile $azContext | Where-Object {$_.ResourceType -in $Types} | Group-Object ResourceType -AsHashTable -AsString }
                            Else { $resHashTable = Get-AzResource -ResourceGroupName $shResourceGroup | Where-Object {$_.ResourceType -in $Types} | Group-Object ResourceType -AsHashTable -AsString }

                            $i = 0
                            Foreach ($ResourceType in $resHashTable.Keys) {
                                Write-Progress -Id 0 -Activity "Azure Virtual Desktop - Gather Resource URI(s)" -Status ("Resource Type: {0} ({1} of {2})" -f $ResourceType,($i + 1),$resHashTable.Keys.Count) -CurrentOperation ("Collecting URI(s) marked for deletion") -PercentComplete (($i / $resHashTable.Keys.Count) * 100)
                                $typeUris = $resHashTable[$ResourceType].ResourceId | _GetRestApiRmUri -ResourceType $ResourceType -azAccessToken $azAccessToken -Verbose
                                $typeUris | ForEach-Object {$avdResourceUris.Add($_)}
                                $i++
                            }
                            Write-Progress -Id 0 -Activity "Completed" -Completed
                        }
                    }
                    Else {
                        [System.Collections.Generic.List[Object]]$avdResourceUris = @()
                        If ($shResourceGroup -eq $ResourceGroupName) {
                            $Types = ('Microsoft.Compute/virtualMachines','Microsoft.Compute/disks','Microsoft.Network/networkInterfaces')
                            $resHashTable = Get-AzResource -ResourceGroupName $ResourceGroupName | Where-Object {$_.ResourceType -in $Types} | Group-Object ResourceType -AsHashTable -AsString

                            $i = 0
                            Foreach ($ResourceType in $resHashTable.Keys) {
                                Write-Progress -Id 0 -Activity "Azure Virtual Desktop - Gather Resource URI(s)" -Status ("Resource Type: {0} ({1} of {2})" -f $ResourceType,($i + 1),$resHashTable.Keys.Count) -CurrentOperation ("Collecting URI(s) marked for deletion") -PercentComplete (($i / $resHashTable.Keys.Count) * 100)
                                $typeUris = $resHashTable[$ResourceType].ResourceId | _GetRestApiRmUri -ResourceType $ResourceType -azAccessToken $azAccessToken -Verbose
                                $typeUris | ForEach-Object {$avdResourceUris.Add($_)}
                                $i++
                            }
                            Write-Progress -Id 0 -Activity "Completed" -Completed
                        }
                        Else {
                            $Types = ('Microsoft.Compute/virtualMachines','Microsoft.Compute/disks','Microsoft.Network/networkInterfaces')
                            If ($altSubscription) { $resHashTable = Get-AzResource -ResourceGroupName $shResourceGroup -DefaultProfile $azContext | Where-Object {$_.ResourceType -in $Types} | Group-Object ResourceType -AsHashTable -AsString }
                            Else { $resHashTable = Get-AzResource -ResourceGroupName $shResourceGroup | Where-Object {$_.ResourceType -in $Types} | Group-Object ResourceType -AsHashTable -AsString }

                            $i = 0
                            Foreach ($ResourceType in $resHashTable.Keys) {
                                Write-Progress -Id 0 -Activity "Azure Virtual Desktop - Gather Resource URI(s)" -Status ("Resource Type: {0} ({1} of {2})" -f $ResourceType,($i + 1),$resHashTable.Keys.Count) -CurrentOperation ("Collecting URI(s) marked for deletion") -PercentComplete (($i / $resHashTable.Keys.Count) * 100)
                                $typeUris = $resHashTable[$ResourceType].ResourceId | _GetRestApiRmUri -ResourceType $ResourceType -azAccessToken $azAccessToken -Verbose
                                $typeUris | ForEach-Object {$avdResourceUris.Add($_)}
                                $i++
                            }
                            Write-Progress -Id 0 -Activity "Completed" -Completed
                        }
                    }

                    If ($avdResourceUris.Count -gt 0) {
                        $stage1Status = $avdResourceUris | Sort-Object Priority | Where-Object {$_.Priority -in (0..2)} | _DeleteAvdResources -azAccessToken $azAccessToken
                        $stage2Status = $avdResourceUris | Sort-Object Priority | Where-Object {$_.Priority -in (3..9)} | _DeleteAvdResources -azAccessToken $azAccessToken

                        $Success = $stage1Status.Succeeded + $stage2Status.Succeeded
                        $Fail = $stage1Status.Failed + $stage2Status.Failed
                        
                        # $DebugPreference = "Inquire"
                        # Write-Debug "DEBUG CHECKPOINT"
                        # $DebugPreference = "SilentlyContinue"

                        If ($stage1Status -OR $stage2Status) {
                            If ($Success -eq $avdResourceUris.Count) { Write-Host ("Successfully removed ALL Azure Virtual Desktop resources" -f $deleteStatus.Succeeded) -ForegroundColor Black -BackgroundColor Green }
                            Else {
                                Write-Host ("`nSuccessfully removed {0} Azure Virtual Desktop resources" -f $Success) -ForegroundColor Black -BackgroundColor Green
                                Write-Host ("`nFailed to remove {0} Azure Virtual Desktop resources" -f $Fail) -ForegroundColor White -BackgroundColor Red
                            }
                        }
                        Else { Write-Warning ("No Resources Deleted") }
                    }
                    
                }
                Else { Write-Warning "User aborted clean up operation!" }


            }
            ElseIf ($hostPool -and -NOT ($shCollection)) {
                Write-Warning ("Failed to collect any Session Host data from HostPool: {0} - Delete resources manually!" -f $HostPoolName)
                Return
            }
            Else {
                Write-Verbose ("Azure Virtual Desktop Session Hosts not found!")
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::New(
                        [System.SystemException]::New(("Failed to collect Session Hosts from HostPool: {0}" -f $HostPoolName)),
                        "SessionHostsNotCollected",
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        ($HostPoolName)
                    )
                )
            }
        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
    }
    END {
        $stopwatch.Stop()
        Write-Host ("`n`rExecution completed in: {0:D2}:{1:D2}.{2:D3}" -f $stopwatch.Elapsed.Minutes,$stopwatch.Elapsed.Seconds,$stopwatch.Elapsed.Milliseconds) -ForegroundColor Black -BackgroundColor Yellow
    }
}