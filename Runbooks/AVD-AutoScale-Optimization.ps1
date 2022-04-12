<#
    .SYNOPSIS
        Runbook designed to optimize a Windows Virtual Desktop (v2) host pool based on a compliance plan.
    .DESCRIPTION
        Once a host pool compliance plan has been created, this runbook will attempt to make it so.  The runbook will run through both 'SCALE-UP' and 'SCALE-DOWN' actions to ensure the host pool becomes compliant based on the capacity requirements.
    .PARAMETER SubscriptionId
        Provide the subscription id where the AVD Host Pool(s) has been created.
    .PARAMETER HostPoolName
        The name of the AVD Host Pool that is being optimized.
    .PARAMETER ResourceGroupName
        ResourceGroupName for the AVD Host Pool.
    .PARAMETER aaAccountName
        Name of the Azure Automation Account, used as the Log Source.
    .PARAMETER laWorkspaceId
        Azure Log Analytics workspace id used to capture runbook logs and compliance status.
    .PARAMETER laWorkspaceKey
        Shared key used to inject data into the Azure Log Analytics workspace.
    .PARAMETER laOptimizeLogName
        Name of the custom log table to be used / created for logging optimization status and events.
    .PARAMETER metrics
        Host Pool metrics from _GetHostPoolMetrics function in the compliance runbook.
    .PARAMETER scaleInfo
        This is the compliance action plan.
    .PARAMETER correlationId
        GUID that unifies events from the compliance runbook to the optimization runbook jobs.
#>
Param (
    [Parameter(Mandatory=$true)]
    [System.String]$SubscriptionId,
    [Parameter(Mandatory=$true)]
    [System.String]$HostPoolName,
    [Parameter(Mandatory=$true)]
    [System.String]$ResourceGroupName,
    [Parameter(Mandatory=$true)]
    [System.String]$aaAccountName,
    [Parameter(Mandatory=$true)]
    [System.String]$laWorkspaceId,
    [Parameter(Mandatory=$true)]
    [System.String]$laWorkspaceKey,
    [Parameter(Mandatory=$true)]
    [System.String]$laOptimizeLogName,
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$metrics,
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$scaleInfo,
    [Parameter(Mandatory=$true)]
    [System.String]$correlationId,
    [Switch]$PassThru
)

#region Helper Functions
Function _NewOptimizeLogEntry {
    <#
        .SYNOPSIS
            Creates a PSCustomObject for Log Analytics logging
        .DESCRIPTION
            Used as a log reporting function to support the dynamic scaling of a Windows Virtual Desktop environment. This function can be called and stored into a variable. The variable can be injected into an Azure Log Analytics workspace Custom Log table or added to an array of messages. This function should be used in conjunction with _WriteLALogEntry.
    #>
    [CmdletBinding()]
    Param (
        $CorrelationId,
        $LogSource,
        $SubscriptionName,
        $ResourceGroup,
        $Entry,
        $HostPoolName,
        $SessionHostName = "null",
        $Operation,
        $Message
    )
    $logEntryTemplate = $null
    $logEntryTemplate = [PSCustomObject][Ordered]@{
        timestamp = [DateTime]::UtcNow.ToString('o')
        correlationId = $CorrelationId
        computer = $LogSource
        subscriptionName = $SubscriptionName
        resourceGroupName = $ResourceGroup
        entryType = $Entry
        hostPoolName = $HostPoolName
        sessionHostName = $SessionHostName
        scaleOperation = $Operation
        logMessage = $Message
    }

    Return $logEntryTemplate
}

Function _WriteLALogEntry {
    <#
        .SYNOPSIS
            Writes a log entry into an Azure Log Analytics workspace in a Custom Log table.
        .DESCRIPTION
            After creating a log entry using the  _NewComplianceLogEntry function, this function will inject the log entry into an Azure Log Analytics workspace. Provide the workspace id, shared key, custom table name, and the $logentry variable. If the custom log exists, it adds the data to the table, otherwise it will create the table.
    #>
    [CmdletBinding()]
    Param (
        $customerId,
        $sharedKey,
        $logName,
        $logMessage,
        [Switch]$PassThru
    )

    BEGIN {
        $VerbosePreference = "SilentlyContinue"
        Function _GetLAAuthorization {
            [CmdletBinding()]
            Param(
                $customerId,
                $sharedKey,
                $date,
                $contentLength,
                $method,
                $contentType,
                $resource
            )
            $xHeaders = "x-ms-date:" + $date
            $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
            $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
            $keyBytes = [Convert]::FromBase64String($sharedKey)
            $sha256 = New-Object System.Security.Cryptography.HMACSHA256
            $sha256.Key = $keyBytes
            $calculatedHash = $sha256.ComputeHash($bytesToHash)
            $encodedHash = [Convert]::ToBase64String($calculatedHash)
            $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
            return $authorization
        }
    }
    PROCESS {
        If ($PassThru) { Return }
        Else {
            $logJSON = $logMessage | ConvertTo-Json
            $body = ([System.Text.Encoding]::UTF8.GetBytes($logJSON))
            $method = "POST"
            $contentType = "application/json"
            $resource = "/api/logs"
            $rfc1123date = [DateTime]::UtcNow.ToString("r")
            $contentLength = $body.Length
            $signature = _GetLAAuthorization -customerId $customerId -sharedKey $sharedKey -date $rfc1123date -contentLength $contentLength -method $method -contentType $contentType -resource $resource 
            $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
            $OMSheaders = @{
                "Authorization"        = $signature;
                "Log-Type"             = $logName;
                "x-ms-date"            = $rfc1123date;
                "time-generated-field" = "Timestamp";
            }
    
            try {
                Invoke-WebRequest -Uri $uri -Method POST -ContentType $contentType -Headers $OMSheaders -Body $body -UseBasicParsing | Out-Null
            }
            catch {
                Write-Warning $_.Exception.Message
            }
        }
    }
}

Function _SetAvdMaintenanceTag {
    <#
        .SYNOPSIS
            Sets a AVD Maintenance tag to $true when a AVD session host does not complete an operation successfully. entry into an Azure Log Analytics workspace. Provide the workspace id, shared key, custom table name, and the $logentry variable. If the custom log exists, it adds the data to the table, otherwise it will create the table.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        $resourceId,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        $vmName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        $sessionHostName,
        [System.String]$jobAction
    )
    begin {
        $tags = @{"AVD-Maintenance"=$true}
    }
    process {
        try {
            $tagUpdate = Update-AzTag -ResourceId $resourceId -Tag $tags -Operation Merge
            If ($tagUpdate) {
                $message = ("[{0}] '{1}' operation did not complete successfully" -f $sessionHostName,$jobAction)
                $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                    -Entry 'WARNING' `
                    -SessionHostName $sessionHostName `
                    -Operation 'ENABLE-MAINTENANCE' `
                    -Message $message
                If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logEntry }
            }
        }
        catch {
            $message = ("[{0}] Failed to update maintenance tag" -f $sessionHostName)
            $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                -Entry 'ERROR' `
                -SessionHostName $sessionHostName `
                -Operation 'UPDATE-TAG' `
                -Message $message
            If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logEntry }
            Continue
        }
    }
}
#endregion

#region Check Azure Automation commands
If ((Get-Command Get-AutomationConnection -ErrorAction SilentlyContinue)) {
    try {
        Write-Output "Found Azure Automation commands, checking for Azure RunAs Connection..."
        # Attempts to use the Azure Run As Connection for automation
        $svcPrncpl = Get-AutomationConnection -Name "AzureRunAsConnection"
        $tenantId = $svcPrncpl.tenantId
        $appId = $svcPrncpl.ApplicationId
        $crtThmprnt = $svcPrncpl.CertificateThumbprint
        Add-AzAccount -ServicePrincipal -TenantId $tenantId -ApplicationId $appId -CertificateThumbprint $crtThmprnt -EnvironmentName AzureCloud | Out-Null
    }
    catch {Write-Error -Exception "Azure RunAs Connection Failure" -Message "Unable to use Azure RunAs Connection" -Category "OperationStopped" -ErrorAction Stop}
}
Else {Write-Output ("Azure Automation commands missing, skipping Azure RunAs Connection...")}
#endregion

#region Create Azure Context(s)
Write-Output ("[{0}] - Connecting to Azure Subscription ({1})" -f (Get-Date),$SubscriptionId)
$azContext = Set-AzContext -Subscription $SubscriptionId
If ($azContext) {Write-Output ("[{0}] - Connected to: {1}" -f (Get-Date),($azContext.Name -split " ")[0])}
Else {
    Write-Output ("[{0}] - Azure Context not found!" -f $SubscriptionId)
    Write-Error -Exception "Invalid Azure Context" -Message ("Unable to create an Azure Context under the {0} subscription" -f ($azContext.Name -split " ")[0]) -Category "OperationStopped" -ErrorAction Stop
}
#endregion

$subscriptionName = $azContext.Subscription.Name

# Create a global variable for the static values used in the logging functions - this variable is splatted against the log entry function
$Global:optimizeLogParams = @{
    CorrelationId = $correlationId
    LogSource = $aaAccountName
    SubscriptionName = $subscriptionName
    ResourceGroup = $ResourceGroupName
    HostPoolName = $HostPoolName
}

# 'SCALE-UP' operation based on the number of session hosts that need to have 'Drain Mode' disabled
If ($scaleInfo.RemoveDrainMode -gt 0) {
    [System.Collections.Generic.List[System.Object]]$logMessages = @() # Empty array to hold several logging entries
    
    $message = ("[{0}] Enabling new sessions on {1} draining session hosts" -f $HostPoolName,$scaleInfo.RemoveDrainMode)
    Write-Output $message
    $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
        -Entry 'INFO' `
        -Operation 'SCALE-UP' `
        -Message $message
    $logMessages.Add($logEntry) # Log entry added to an array

    # Loop through session hosts based on availability matrix and selecting a random number of session hosts to disable drain mode
    $metrics.sessionHosts | 
        Where-Object {$_.AllowNewSession -eq $false -and $_.sessionHostStatus -eq "Available" -and $_.avdMaintenance -eq $false -and $_.vmStatus -eq "vm running"} | 
        Get-Random -Count $scaleInfo.RemoveDrainMode |
        ForEach-Object {
            $message = ("[{0}] Enabling new sessions" -f $_.sessionHostName)
            Write-Output $message
            $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                -Entry 'INFO' `
                -SessionHostName $_.sessionHostName `
                -Operation 'ENABLE-NEW-SESSIONS' `
                -Message $message `
                -Verbose
            $logMessages.Add($logEntry) # Log entry added to an array
            # Remove drain mode
            Update-AzWvdSessionHost -Name $_.sessionHostName -HostPoolName $hostPoolName -ResourceGroupName $_.resourceGroupName -AllowNewSession:$true | Out-Null
        }
    
        If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logMessages } # Write the array of log events to Log Analytics
}

# 'SCALE-UP' operation based on the number of session hosts that need to be started
If ($scaleInfo.StartVMs -gt 0) {
    $jobAction = "START-VM"
    [System.Collections.Generic.List[System.Object]]$logMessages = @() # Empty array to hold several logging entries
    $message = ("[{0}] Attempting to start {1} virtual machines" -f $HostPoolName,$scaleInfo.StartVMs)
    Write-Output $message
    $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
        -Entry 'INFO' `
        -Operation 'SCALE-UP' `
        -Message $message
    $logMessages.Add($logEntry) # Log entry added to an array

    # Loop through session hosts based on availability matrix and select random number of VM(s) to start (bring into service)
    [System.Collections.Generic.List[System.Object]]$sessionHostsToStart = @()
    $metrics.sessionHosts | 
        Where-Object { ($_.sessionHostStatus -eq "Shutdown" -OR $_.sessionHostStatus -eq "unavailable") -and $_.vmStatus -eq "vm deallocated" -and $_.avdMaintenance -eq $false } |
        Get-Random -Count $scaleInfo.StartVMs | 
        ForEach-Object { $sessionHostsToStart.Add($_) } # Loops through each session host and adds to the vms to start collection if the where clause is met

    If (-NOT $sessionHostsToStart) {
        $message = ("[{0}] No Session Hosts found to complete {1} operations" -f $HostPoolName,$jobAction)
        Write-Output $message
        $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
            -Entry 'ERROR' `
            -Operation 'SCALE-UP' `
            -Message $message
        $logMessages.Add($logEntry) # Log entry added to an array
    }
    Else {
        Foreach ($sessionHost in $sessionHostsToStart) {
            # Start the VM with -NoWait
            Start-AzVM -Name $sessionHost.vmName -ResourceGroupName $sessionHost.ResourceGroupName -Confirm:$false -NoWait | Out-Null
            
            $message = ("[{0}] Initiated '{1}' operation" -f $sessionHost.sessionHostName,$jobAction)
            Write-Output $message
            $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                -Entry 'INFO' `
                -SessionHostName $sessionHost.sessionHostName `
                -Operation $jobAction `
                -Message $message
            $logMessages.Add($logEntry) # Log entry added to an array
        }
        If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logMessages } # Write the array of log events to Log Analytics

        $logMessages.Clear() # Clears the array to hold new logging events
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew() # Create stopwatch to prevent long running validation loop
        $vmStatusCheck = $true
        While ($vmStatusCheck) {
            If ($stopwatch.Elapsed.TotalMinutes -ge 15) {
                # Assume any validation check exceeding 10 minutes is either stuck or indicates a problem
                $message = ("[{0}] '{1}' validation exceeded the time allotted (15 minutes)" -f $hostPoolName,$jobAction)
                Write-Output $message
                $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                    -Entry 'WARNING' `
                    -Operation 'SESSION-HOST-STATUS' `
                    -Message $message
                If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logEntry } # Write the log entry to Log Analytics

                #$sessionHostsToValidate | ForEach-Object {
                $sessionHostsToStart | ForEach-Object {
                    # Any session host started that isn't reporting as 'available' is set to maintenance
                    $avdStatus = Get-AzWvdSessionHost -HostPoolName $hostPoolName -ResourceGroupName $_.ResourceGroupName -Name $_.sessionHostName | ForEach-Object {$_.Status}
                    If ($avdStatus -ne "Available") {
                        $message = ("[{0}] '{1}' operation did not complete OR the session host is not 'available'" -f $_.sessionHostName,$jobAction)
                        Write-Output $message
                        $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                            -Entry 'WARNING' `
                            -SessionHostName $_.sessionHostName `
                            -Operation $jobAction `
                            -Message $message
                        If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logEntry } # Write the log entry to Log Analytics
                        $_ | _SetAvdMaintenanceTag -jobAction $jobAction
                        Stop-AzVM -ResourceGroupName $_.ResourceGroupName -Name $_.vmName -NoWait -Force | Out-Null
                    }
                    Else {
                        # Any session host showing 'available' has drain mode disabled
                        $message = ("[{0}] '{1}' operation completed successfully" -f $_.sessionHostName,$jobAction)
                        Write-Output $message
                        $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                            -Entry 'INFO' `
                            -SessionHostName $_.sessionHostName `
                            -Operation $jobAction `
                            -Message $message
                        $logMessages.Add($logEntry) # Log entry added to an array
                        Update-AzWvdSessionHost -Name $_.sessionHostName -HostPoolName $hostPoolName -ResourceGroupName $_.resourceGroupName -AllowNewSession:$true | Out-Null
                    }
                }
                $stopwatch.Stop()
                $vmStatusCheck = $false
            }
            Else {
                $sessionHostsComplete = 0 # Counts the session hosts that are available after a start event
                $sessionHostsToStart | ForEach-Object {
                    $avdStatus = Get-AzWvdSessionHost -HostPoolName $hostPoolName -ResourceGroupName $_.ResourceGroupName -Name $_.sessionHostName | ForEach-Object {$_.Status}
                    Write-Output ("[{0}] Session Host Status: {1}" -f $_.sessionHostName,$avdStatus)
                    If ($avdStatus -eq "Available") { $sessionHostsComplete++ }
                }
                
                Write-Output ("Session Hosts To Start: {0}" -f $sessionHostsToStart.Count)
                Write-Output ("Session Hosts Complete: {0}" -f $sessionHostsComplete)
                If ($sessionHostsToStart.Count -eq $sessionHostsComplete) {
                    # Log and break loop if all session hosts report complete
                    $sessionHostsToStart | ForEach-Object {
                        $message = ("[{0}] '{1}' operation completed successfully" -f $_.sessionHostName,$jobAction)
                        $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                            -Entry 'INFO' `
                            -SessionHostName $_.sessionHostName `
                            -Operation $jobAction `
                            -Message $message
                        $logMessages.Add($logEntry) # Log entry added to an array
                        Update-AzWvdSessionHost -Name $_.sessionHostName -HostPoolName $hostPoolName -ResourceGroupName $_.resourceGroupName -AllowNewSession:$true | Out-Null
                    }
                    $stopwatch.Stop()
                    $vmStatusCheck = $false
                }
                Start-Sleep  -Milliseconds 2500
            }
        }
    }
    
    $message = ("[{0}] Scale up operation finished" -f $hostPoolName)
    Write-Output $message
    $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
        -Entry 'INFO' `
        -Operation 'SCALE-UP' `
        -Message $message
    $logMessages.Add($logEntry) # Log entry added to an array
    If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logMessages } # Write the array of log events to Log Analytics
}

# 'SCALE-DOWN' operation based on the number of session hosts that need to be drained or stopped
If ($scaleInfo.DrainAndStopVMs -gt 0) {
    [System.Collections.Generic.List[System.Object]]$logMessages = @() # Empty array to hold several logging entries
    $message = ("[{0}] Attempting to drain and stop {1} virtual machines" -f $HostPoolName,$scaleInfo.DrainAndStopVMs)
    Write-Output $message
    $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
        -Entry 'INFO' `
        -Operation 'SCALE-DOWN' `
        -Message $message
    $logMessages.Add($logEntry) # Log entry added to an array

        # Loop through session hosts based on availability matrix, add an action property to the host object with drain as the default action
    $shHashTable = $metrics.sessionHosts | Where-Object { 
        $_.sessionHostStatus -eq "available" -and 
        $_.vmStatus -eq "vm running" -and 
        $_.avdMaintenance -eq $false
    } | Group-Object AllowNewSession -AsHashTable -AsString

    [System.Collections.Generic.List[System.Object]]$sessionHostsToStop = @()
    Switch ($shHashTable.Keys | Sort-Object) {
        "False" {
            Foreach ($item in $shHashTable["False"]) {
                $item | Add-Member -Name "action" -MemberType NoteProperty -Value "drain"
                $sessionHostsToStop.Add($item)
                If ($sessionHostsToStop.count -eq $scaleinfo.DrainAndStopVMs) { Break }
            }
        }
        "True" {
            If ($sessionHostsToStop.count -eq $scaleinfo.DrainAndStopVMs) { Break }
            Foreach ($item in $shHashTable["True"]) {
                $item | Add-Member -Name "action" -MemberType NoteProperty -Value "drain"
                $sessionHostsToStop.Add($item)
                If ($sessionHostsToStop.count -eq $scaleinfo.DrainAndStopVMs) { Break }
            }
        }
    }

    Foreach ($objSessionHost in $sessionHostsToStop) {
        # Set the action to stop if there are NO sessions
        If ($objSessionHost.session -eq 0 -and (Get-AzWvdSessionHost -Name $objSessionHost.sessionHostName -HostPoolName $HostPoolName -ResourceGroupName $objSessionHost.resourceGroupName).Session -eq 0) {
            $message = ("[{0}] No sessions found, setting action to STOP" -f $objSessionHost.sessionHostName)
            Write-Output $message
            $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                -Entry 'INFO' `
                -Operation 'SCALE-DOWN' `
                -SessionHostName $objSessionHost.sessionHostName `
                -Message $message
            $logMessages.Add($logEntry) # Log entry added to an array
            $objSessionHost.action = "Stop"
        }
        Else {
            # Session host shows sessions, get current sessions to determine which are active vs disconnected
            $Sessions = Get-AzWvdUserSession -SessionHostName $objSessionHost.sessionHostName -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName
            If ($Sessions.SessionState -contains "Active") {
                # Session hosts with active sessions are set to drain
                $message = ("[{0}] {1} active sessions remaining, setting action to DRAIN" -f $objSessionHost.sessionHostName,($Sessions | Where-Object {$_.SessionState -eq "Active"}).Count)
                Write-Output $message
                $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                    -Entry 'INFO' `
                    -Operation 'DISABLE-NEW-SESSIONS' `
                    -SessionHostName $objSessionHost.sessionHostName `
                    -Message $message
                $logMessages.Add($logEntry) # Log entry added to an array
            }
            ElseIf ($Sessions.SessionState -contains "Disconnected") {
                # Session hosts with disconnected sessions need to be checked for their duration.
                $Sessions | Where-Object {$_.SessionState -eq "Disconnected"} | ForEach-Object {
                    $duration = $_.CreateTime.ToUniversalTime().Subtract([DateTime]::UtcNow)
                    If ($duration.TotalHours -lt 3) { $validSessions++ } # Less than 3 hrs disconnected, don't stop the VM
                }

                If ($validSessions -gt 0) {
                    # Session host has valid sessions, action set to drain only
                    $message = ("[{0}] {1} valid sessions remaining (< 8hr disconnected), setting action to DRAIN" -f $objSessionHost.sessionHostName,$validSessions)
                    Write-Output $message
                    $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                        -Entry 'INFO' `
                        -Operation 'DISABLE-NEW-SESSIONS' `
                        -SessionHostName $objSessionHost.sessionHostName `
                        -Message $message
                    $logMessages.Add($logEntry) # Log entry added to an array
                }
                Else {
                    # Session host has NO valid sessions, action set to stop
                    $message = ("[{0}] No valid sessions remaining, setting action to STOP" -f $objSessionHost.sessionHostName)
                    Write-Output $message
                    $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                        -Entry 'INFO' `
                        -Operation 'STOP-VM' `
                        -SessionHostName $objSessionHost.sessionHostName `
                        -Message $message
                    $logMessages.Add($logEntry) # Log entry added to an array
                    $objSessionHost.action = 'stop'
                }
            }
            Else {
                # Any other session state, set the action to stop
                $message = ("[{0}] No valid sessions remaining, setting action to STOP" -f $objSessionHost.sessionHostName)
                Write-Output $message
                $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                    -Entry 'INFO' `
                    -Operation 'STOP-VM' `
                    -SessionHostName $objSessionHost.sessionHostName `
                    -Message $message
                $logMessages.Add($logEntry) # Log entry added to an array
                $objSessionHost.action = 'stop'
            }
        }
    }

    If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logMessages } # Write the array of log events to Log Analytics

    If (-NOT $sessionHostsToStop) {
        $message = ("[{0}] No session hosts to scale down" -f $HostPoolName)
        Write-Output $message
        $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
            -Entry 'ERROR' `
            -Operation 'SCALE-DOWN' `
            -Message $message
        If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logEntry } # Write the log entry to Log Analytics
    }
    Else {
        [System.Collections.Generic.List[System.Object]]$stopVMJobs = @() # Empty array to hold background jobs
        Foreach ($sessionHost in $sessionHostsToStop) {
            # Check the action, drain vs stop
            If ($sessionHost.action -eq "drain") {
                Update-AzWvdSessionHost -Name $sessionHost.sessionHostName -HostPoolName $hostPoolName -ResourceGroupName $sessionHost.resourceGroupName -AllowNewSession:$false | Out-Null

                $message = ("[{0}] Disabling new sessions" -f $sessionHost.sessionHostName)
                Write-Output $message
                $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                    -Entry 'INFO' `
                    -SessionHostName $sessionHost.sessionHostName `
                    -Operation 'DISABLE-NEW-SESSIONS' `
                    -Message $message
                If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logEntry } # Write the log entry to Log Analytics
            }
            Else {
                # Stop the VM as a job and store the job details into an array
                Update-AzWvdSessionHost -Name $sessionHost.sessionHostName -HostPoolName $hostPoolName -ResourceGroupName $sessionHost.resourceGroupName -AllowNewSession:$false | Out-Null
                $objJob = Stop-AzVM -Name $sessionHost.vmName -ResourceGroupName $sessionHost.resourceGroupName -Force -AsJob
                $stopVMJobs.Add($objJob) # Add background job to empty array

                $message = ("[{0}] Initiated 'STOP-VM' operation" -f $sessionHost.sessionHostName)
                Write-Output $message
                $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                    -Entry 'INFO' `
                    -SessionHostName $sessionHost.sessionHostName `
                    -Operation 'STOP-VM' `
                    -Message $message
                If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logEntry } # Write the log entry to Log Analytics
            }
        }
        
        # Wait for jobs to complete or maxDuration to expire
        $maxDuration = 10
        $message = ("[{0}] Waiting on {1} background job operations (< {2} minutes)" -f $HostPoolName,$stopVMJobs.Count,$maxDuration)
        $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
            -Entry 'INFO' `
            -Operation 'WAIT-ON-JOBS' `
            -Message $message
        If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logEntry }
    
        $timeSpan = [timespan]::FromMinutes($maxDuration)
        While (($stopVMJobs | Where-Object {$_.State -eq "Running"}).Count -gt 0) {
            $utcNow = [DateTime]::UtcNow
            Foreach ($Job in ($stopVMJobs | Where-Object {$_.State -eq "Running"})) {
                If ($utcNow.Subtract($Job.PSBeginTime.ToUniversalTime()) -gt $timeSpan) {
                    Write-Output ("{0} Job running duration exceeded 10 minutes!" -f $job.Name)
                    $Job | Stop-Job -Confirm:$false
                    $Job | Remove-Job
                }
            }
            Start-Sleep -Milliseconds 2500
        }

        Write-Output $stopVMJobs | Group-Object State -NoElement

        [System.Collections.Generic.List[System.Object]]$sessionHostsToValidate = @() # Empty array for jobs that completed successfully and need final validation to take out of service
        Foreach ($job in $stopVMJobs) {
            $jobName = $job.name.split(" ")[-1].Trim("'") # Get the name of the VM from the background job
            If ($job.State -ne "Completed") {
                # Stop VM job was not completed, set session host into Maintenance
                $objSessionHost = $sessionHostsToStop | Where-Object {$_.action -eq "stop" -and $_.vmName -eq $jobName}

                $message = ("[{0}] 'STOP-VM' operation did not complete or failed" -f $objSessionHost.sessionHostName)
                Write-Output $message
                $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                    -Entry 'WARNING' `
                    -SessionHostName $objSessionHost.sessionHostName `
                    -Operation 'STOP-VM' `
                    -Message $message
                If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logEntry } # Write the log entry to Log Analytics

                $objSessionHost | _SetAvdMaintenanceTag -jobAction 'STOP-VM'
            }
            Else {
                # Stop VM job was completed
                $objSessionHost = $sessionHostsToStop | Where-Object {$_.action -eq "stop" -and $_.vmName -eq $jobName}
                $sessionHostsToValidate.Add($objSessionHost)
            }
        }

        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew() # Create stopwatch to prevent long running validation loop
        $vmStatusCheck = $true
        While ($vmStatusCheck) {
            If ($stopwatch.Elapsed.TotalMinutes -ge 10) {
                
                $message = ("[{0}] 'STOP-VM' validation exceeded the time allotted (10 minutes)" -f $hostPoolName)
                Write-Output $message
                $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                    -Entry 'WARNING' `
                    -Operation 'SESSION-HOST-STATUS' `
                    -Message $message
                If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logEntry } # Write the log entry to Log Analytics
    
                $sessionHostsToValidate | ForEach-Object {
                    # Any session host stopped that isn't reporting as unavailable or deallocated is set to maintenance
                    $avdStatus = Get-AzWvdSessionHost -HostPoolName $hostPoolName -ResourceGroupName $_.ResourceGroupName -Name $_.sessionHostName | ForEach-Object {$_.Status}
                    $vmStatus = Get-AzVM -Name $_.vmName -ResourceGroupName $_.resourceGroupName -Status | ForEach-Object {$_.Statuses[-1].DisplayStatus}
                    If ($avdStatus -ne "Unavailable" -or $vmStatus -ne "vm deallocated") {
                        $_ | _SetAvdMaintenanceTag -jobAction 'STOP-VM'
                    }
                }
                $stopwatch.Stop()
                $vmStatusCheck = $false
            }
            Else {
                $sessionHostsComplete = 0 # Counts the session hosts that are available after a start event
                $sessionHostsToValidate | ForEach-Object {
                    $avdStatus = Get-AzavdSessionHost -HostPoolName $hostPoolName -ResourceGroupName $_.ResourceGroupName -Name $_.sessionHostName | ForEach-Object {$_.Status}
                    $vmStatus = Get-AzVM -Name $_.vmName -ResourceGroupName $_.resourceGroupName -Status | ForEach-Object {$_.Statuses[-1].DisplayStatus}
                    If ($avdStatus -eq "Unavailable" -or $vmStatus -eq "vm deallocated") {
                        $message = ("[{0}] 'STOP-VM' operation completed successfully" -f $_.sessionHostName)
                        Write-Output $message
                        $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
                            -Entry 'INFO' `
                            -SessionHostName $_.sessionHostName `
                            -Operation 'STOP-VM' `
                            -Message $message
                        If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logEntry } # Write the log entry to Log Analytics
                        $sessionHostsComplete++
                    }
                }

                If ($sessionHostsToValidate.Count -eq $sessionHostsComplete) {
                    # Log and break loop if all session hosts report complete
                    $stopwatch.Stop()
                    $vmStatusCheck = $false
                }
                Start-Sleep  -Milliseconds 2500
            }
        }

        $message = ("[{0}] Scale down operation finished" -f $hostPoolName)
        Write-Output $message
        $logEntry = _NewOptimizeLogEntry @optimizeLogParams `
            -Entry 'INFO' `
            -Operation 'SCALE-DOWN' `
            -Message $message
        If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laOptimizeLogName -logMessage $logEntry } # Write the log entry to Log Analytics
    }
}