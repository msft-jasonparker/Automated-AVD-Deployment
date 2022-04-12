<#
    .SYNOPSIS
        Runbook designed to check a Windows Virtual Desktop (v2) Host Pool compliance state.
    .DESCRIPTION
        A AVD Host Pool is compliant when the number of session hosts providing access are within a specified range based on the time of day.  If the time of day is during 'OnPeak' hours, the runbook will determine compliance based on the overall session load of the host pool.  If the host pool session load is above the high threshold, the host pool will try to 'scale-up'. If the host pool session load is below the min threshold, the host pool will try to 'scale-down'. Anything in the middle is considered 'optimal'. During 'OffPeak' times or weekends, session load is not evaluated and only raw session host counts are considered. If the host pool is 'not-compliant', the optimization runbook is called to attempt and make the host pool right sized.
    .PARAMETER subscriptionId
        Provide the subscription id where the AVD Host Pool(s) has been created.
    .PARAMETER aaAccountName
        Name of the Azure Automation Account. Used as the log source in the logging function.
    .PARAMETER aaResourceGroupName
        ResourceGroup Name where the Azure Automation Account (aaAccountName) was created.
    .PARAMETER aaSubscriptionId
        Subscription id for the Azure Automation Account.
    .PARAMETER laWorkspaceId
        Azure Log Analytics workspace id used to capture runbook logs and compliance status.
    .PARAMETER laWorkspaceKey
        Shared key used to inject data into the Azure Log Analytics workspace.
    .PARAMETER laComplianceLogName
        Name of the custom log table to be used / created for logging compliance status and events.
    .PARAMETER TZOffSetFromGMT
        Used to create the local time used in the logging events.
    .PARAMETER startPeakUsageTime
        Start of 'OnPeak' hours - use military time format HH:mm.
    .PARAMETER endPeakUsageTime
        End of 'OnPeak' hours - use military time format HH:mm.
    .PARAMETER sessionHeadroomPercent
        Whole number percent of headroom to add during session load calculations.  The larger the number the more padding that will be added to the overall host pool capacity.
    .PARAMETER sessionMaxThreshold
        Whole number percent used in determining the current session load (percent) versus the current capacity of the host pool. Over this number and the host pool will 'scale-up'.
    .PARAMETER sessionMinThreshold
        Whole number percent used in determining the current session load (percent) versus the current capacity of the host pool. Below this number and the host pool will 'scale-down'.
#>
[CmdletBinding()]
Param (
    [System.String]$subscriptionId = "",
    [System.String]$aaAccountName = "",
    [System.String]$aaResourceGroupName = "",
    [System.String]$aaSubscriptionId = "",
    [System.String]$laWorkspaceId = "",
    [System.String]$laWorkspaceKey = "",
    [System.String]$laComplianceLogName = "AVD_AutoScale_Compliance_CL",
    [System.Int32]$TZOffSetFromGMT = 4,
    [System.String]$startWarmUpTime = "07:30",
    [System.String]$startPeakUsageTime = "10:30",
    [System.String]$endPeakUsageTime = "20:00",
    [Int]$sessionHeadroomPercent = 35,
    [Int]$sessionMaxThreshold = 70,
    [Int]$sessionMinThreshold = 40,
    [Switch]$PassThru
)

#region Helper funcitons
Function _NewComplianceLogEntry {
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
        $TimeOfUse,
        $HostPoolState = "CHECKING",
        $ComplianceTask,
        $ComplianceState,
        $SessionHostCount = 0,
        $Available = 0,
        $Draining = 0,
        $Unavailable = 0,
        $Needed = 0,
        $MaxSessions = 0,
        $Sessions = 0,
        $Load = 0,
        $Message
    )
    $logEntryTemplate = [PSCustomObject][Ordered]@{
        timestamp = [DateTime]::UtcNow.ToString('o')
        correlationId = $CorrelationId
        computer = $LogSource
        subscriptionName = $SubscriptionName
        resourceGroupName = $ResourceGroup
        entryType = $Entry
        hostPoolName = $HostPoolName
        timeOfUse = $TimeOfUse
        hostPoolState = $HostPoolState
        complianceTask = $ComplianceTask
        complianceState = $ComplianceState
        totalSessionHosts = $SessionHostCount
        sessionHostsAvailable = $Available
        sessionHostsDraining = $Draining
        sessionHostsUnavailable = $Unavailable
        sessionHostsNeeded = $Needed
        maxNumberOfSessions = $MaxSessions
        currentSessions = $Sessions
        currentSessionLoad = $Load
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

Function _GetSessionHostInfo {
    <#
    .SYNOPSIS
        Gets all the session hosts in a Windows Virtual Desktop hostpoot and gathers AVD and VM specific information
    .DESCRIPTION
        This function is the core of this script. It collects specific information about the session hosts (AVD) and the VM (VM status) to provide a holistic view of the host pool and its ability to serve users.
    .OUTPUTS
        The output of this function is an array of custom objects. The custom object contains the following data:
            - sessionHostName (AVD)
            - vmName (VM)
            - sessionHostStatus (AVD)
            - allowNewSesssion (AVD)
            - lastHeartBeat (AVD)
            - lastUpdateTime (AVD)
            - statusTimestamp (AVD)
            - session (AVD)
            - resourceId (VM)
            - resourceGroupName (VM)
            - avdMaintenance (VM Custom Tag)
            - avdPostDscComplete (VM Custom Tag)
            - avdGroup (VM Custom Tag)
            - location (VM)
            - vmStatus (VM)
    #>
    [CmdletBinding()]
    Param (
        $hostPoolName,
        $resourceGroupName,
        [Switch]$PassThru
    )
    [System.Collections.Generic.List[Object]]$sessionHostInfo = @()
    $avdshArray = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -Debug:$false
    $azvmArray = Get-AzVM -ResourceGroupName $resourceGroupName -Status | Group-Object Name -AsHashTable -AsString -Debug:$false
    
    Foreach ($avdsh in $avdshArray) {
        $objSessionHost = @{
            sessionHostName = ($avdsh.Name.Split("/")[-1]).ToLower()
            vmName = ($avdsh.Name.Split("/")[-1].Split(".")[0]).ToLower()
            sessionHostStatus = ([System.String]$avdsh.Status).ToLower()
            allowNewSession = $avdsh.AllowNewSession
            lastHeartBeat = $avdsh.LastHeartBeat
            lastUpdateTime = $avdsh.LastUpdateTime
            statusTimestamp = $avdsh.StatusTimestamp
            session = $avdsh.Session
        }

        try {
            If ($azvmArray.Keys -contains $objSessionHost.vmName) {
                $objSessionHost.resourceId = ($azvmArray[$objSessionHost.vmName].Id).ToLower()
                $objSessionHost.resourceGroupName = ($azvmArray[$objSessionHost.vmName].ResourceGroupName).ToLower()
                $objSessionHost.avdMaintenance = $azvmArray[$objSessionHost.vmName].Tags["AVD-Maintenance"]
                $objSessionHost.location = ($azvmArray[$objSessionHost.vmName].location).ToLower()
                $objSessionHost.vmStatus = ($azvmArray[$objSessionHost.vmName].PowerState).ToLower()
            }
            Else {
                $objVirtualMachine = Get-AzVM -Name $objSessionHost["vmName"] -Status -Debug:$false
                If ($objVirtualMachine.Count -eq 1) {
                    If ($objVirtualMachine.Name -contains $objSessionHost.vmName) {
                        $objSessionHost.resourceGroupName = ($objVirtualMachine.Id).ToLower()
                        $objSessionHost.resourceGroupName = ($objVirtualMachine.ResourceGroupName).ToLower()
                        $objSessionHost.avdMaintenance = $objVirtualMachine.Tags["AVD-Maintenance"]
                        $objSessionHost.location = ($objVirtualMachine.location).ToLower()
                        $objSessionHost.vmStatus = ($objVirtualMachine.PowerState).ToLower()
                    }
                    Else {
                        Throw ("[{0}] Found Azure virtual machine, but it is not a session host in {1}" -f $objSessionHost.vmName,$HostPoolName)
                    }
                }
                ElseIf ($objVirtualMachine.Count -gt 1) {
                    Throw ("[{0}] Found {1} Azure virtual machines with the same name" -f $objSessionHost.vmName,$objVirtualMachine.Count)
                }
                Else {
                    Throw ("[{0}] No Azure virtual machine found" -f $objSessionHost.vmName)
                }
            }
            $sessionHostInfo.Add([PSCustomObject]$objSessionHost)
        }
        catch {
            $message = $_.Exception.Message
            $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
                -Entry 'ERROR' `
                -ComplianceTask 'SESSION-HOST-INFO' `
                -ComplianceState 'UNKNOWN' `
                -Message $message
            If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry }
        }
    }
    $message = ("[{0}] Collected session host and virtual machine information" -f $hostPoolName)
    $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
        -Entry 'INFO' `
        -ComplianceTask 'SESSION-HOST-INFO' `
        -ComplianceState 'UNKNOWN' `
        -SessionHostCount $sessionHostInfo.Count `
        -Message $message
    If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry }

    Return $sessionHostInfo
}

Function _GetMinimumSessionHosts {
    <#
    .SYNOPSIS
        Simple function to calculate the minimum number of session hosts needed based on a default value and percentage of the total session host count
    .OUTPUTS
        Returns an integer specifying the minimum session hosts needed in a host pool group
    #>
    Param (
        # 
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$SessionHosts,
        
        # 
        [Parameter(Mandatory=$true)]
        [ValidateSet("WarmUp","OnPeak","OffPeak")]
        [System.String]$Plan,

        # 
        [Parameter(Mandatory=$false)]
        [Int32]$MinimumDefaultValue = 2
    )
    Switch ($Plan) {
        "WarmUp" { $PlanScalePercent = 0.25 }
        "OnPeak" { $PlanScalePercent = 0.15 }
        "OffPeak" { $PlanScalePercent = 0.05 }
    }
    Write-Verbose ("AVD Usage Plan: {0} ({1}%)" -f $Plan, ($PlanScalePercent * 100))
    $minimumSessionHosts = [math]::Ceiling($SessionHosts.Count * $PlanScalePercent)
    If ($minimumSessionHosts -lt $MinimumDefaultValue) {
        Write-Verbose ("Minimum Session Hosts: {0} (default)" -f $MinimumDefaultValue)
        Return $MinimumDefaultValue
    }
    Else {
        Write-Verbose ("Minimum Session Hosts: {0} (plan based)" -f $minimumSessionHosts)
        Return $minimumSessionHosts
    }
}

Function _GetHostPoolMetrics {
    <#
    .SYNOPSIS
        Gathers counts of session hosts based on status for a given host pool
    .DESCRIPTION
        Creates a hashtable. The hashtable keys are based on the avdGroup property (custom VM Tag) used during a AVD deployment. Each key is based on a group (i.e. A, B, etc) and the key contains the host pool metrics (number of session hosts based on status)
    #>
    [CmdletBinding()]
    Param (
        $hostPoolName,
        $resourceGroupName,
        $minimumSessionHosts,
        $hostPoolSessionLimit,
        $sessionHosts,
        [Switch]$PassThru
    )

    $drainingSessionHosts = ($sessionHosts | Where-Object {$_.AllowNewSession -eq $false -and $_.sessionHostStatus -eq "available" -and $_.avdMaintenance -eq $false -and $_.vmStatus -eq "vm running"} | Measure-Object).Count
    $availableSessionHosts = ($sessionHosts | Where-Object {$_.AllowNewSession -eq $true -and $_.sessionHostStatus -eq "available" -and $_.avdMaintenance -eq $false -and $_.vmStatus -eq "vm running"} | Measure-Object).Count
    $unavailableSessionHosts = ($sessionHosts | Where-Object { ($_.sessionHostStatus -eq "unavailable" -or $_.sessionHostStatus -eq "shutdown") -or $_.avdMaintenance -eq $true -or $_.vmStatus -ne "vm running"} | Measure-Object).Count
    $totalSessionHosts = ($sessionHosts | Measure-Object).Count
    $currentUserSessions = ($sessionHosts | Measure-Object -Property session -Sum).Sum
    $maxUserSessions = (($sessionHosts | Measure-Object).Count * $hostPoolSessionLimit)
        
    [System.Collections.Generic.List[Object]]$complianceMessages = @()

    # Determining Host Pool User Session Load based on Session Hosts (sessionLoad is a whole number percentage based on capacity)
    If ($currentUserSessions -eq 0 -OR ($availableSessionHosts -eq 0 -AND $drainingSessionHosts -eq 0)) {
        # No sessions found or no session hosts available or draining; setting load to 0%
        $sessionLoad = 0
        If ($currentUserSessions -eq 0) {$message = ("[{0}] No user sessions found, session load is 0%" -f $hostPoolName)}
        Else {$message = ("[{0}] No session hosts (available or draining) found, session load is 0%" -f $hostPoolName)}
    }
    Else {
        # Session load percentage is based on the number of available and draining session hosts and the session limit    
        $availableSessions = $availableSessionHosts * $hostPoolSessionLimit
        $sessionLoad = [math]::Ceiling($currentUserSessions / $availablesessions * 100)
        $message = ("[{0}] Checking host pool capacity, session load is {1}% (Min: {2} | Max: {3} )" -f $hostPoolName,$sessionLoad,$sessionMinThreshold,$sessionMaxThreshold)
    }
    
    Write-Verbose $message
    $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
        -Entry 'INFO' `
        -ComplianceTask 'HOST-POOL-METRICS' `
        -ComplianceState 'UNKNOWN' `
        -Available $availableSessionHosts `
        -Draining $drainingSessionHosts `
        -Unavailable $unavailableSessionHosts `
        -SessionHostCount $totalSessionHosts `
        -MaxSessions $maxUserSessions `
        -Sessions $currentUserSessions `
        -Load $sessionLoad `
        -Message $message
    $complianceMessages.Add($complianceLogEntry)

    # Using the sessionLoad percentage to validate if the Host Pool is above or below thresholds and recommending a number of Needed Session Hosts to be online.
    If ($sessionLoad -ge $SessionMaxThreshold) {
        # sessionLoad is over the Max Threshold
        $sessionHostsNeeded = [math]::Ceiling(($availableSessionHosts * $SessionHeadroomPercent)/100 + $availableSessionHosts)
        $complianceState = "ABOVE-THRESHOLD"
        $message = ("[{0}] Current session load is: {1} ({2}%)" -f $hostPoolName,$complianceState,$SessionMaxThreshold)
    }
    ElseIf ($sessionLoad -le $SessionMinThreshold) {
        # sessionLoad is below Min Threshold
        #Write-Output ("`$sessionHostsNeeded = [math]::Ceiling((($currentUserSessions * ($sessionHeadroomPercent / 100)) + $currentUserSessions) / $hostPoolSessionLimit)")
        $sessionHostsNeeded = [math]::Ceiling((($currentUserSessions * ($sessionHeadroomPercent / 100)) + $currentUserSessions) / $hostPoolSessionLimit)
        #$sessionHostsNeeded = [math]::Ceiling($currentUserSessions / $hostPoolSessionLimit)
        $complianceState = "BELOW-THRESHOLD"
        $message = ("[{0}] Current session load is: {1} ({2}%)" -f $hostPoolName,$complianceState,$SessionMinThreshold)
    }
    Else {
        # sessionLoad is Optimal
        $sessionHostsNeeded = $availableSessionHosts
        $complianceState = "OPTIMAL"
        $message = ("[{0}] Current session load is: {1} ({2}%)" -f $hostPoolName,$complianceState,$sessionLoad)
    }

    If ($sessionHostsNeeded -lt $minimumSessionHosts) {
        $message = ("[{0}] Current session hosts needed ({1}) is BELOW the minimum session host ({2}) value based on the 'Time of Day', setting the session hosts needed to the minimum session host value." -f $hostPoolName,$sessionHostsNeeded,$minimumSessionHosts)
        $sessionHostsNeeded = $minimumSessionHosts
        $complianceState = "BELOW-MINIMUM-HOSTS"
    }

    Write-Verbose $message
    $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
        -Entry 'INFO' `
        -ComplianceTask 'HOST-POOL-METRICS' `
        -ComplianceState $complianceState `
        -Available $availableSessionHosts `
        -Draining $drainingSessionHosts `
        -Unavailable $unavailableSessionHosts `
        -SessionHostCount $totalSessionHosts `
        -MaxSessions $maxUserSessions `
        -Needed $sessionHostsNeeded `
        -Sessions $currentUserSessions `
        -Load $sessionLoad `
        -Message $message
    $complianceMessages.Add($complianceLogEntry)
    
    If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry }
    
    $hostPoolMetrics = [PSCustomObject]@{
        hostPoolName = $hostPoolName
        sessionHosts = $sessionHosts
        complianceState = $complianceState
        draining = $drainingSessionHosts
        available = $availableSessionHosts
        unavailable = $unavailableSessionHosts
        total = $totalSessionHosts
        needed = $sessionHostsNeeded
        maxSessions = $maxUserSessions
        hostPoolSessions = $currentUserSessions
        hostPoolLoad = $sessionLoad
    }
    
    Return $hostPoolMetrics
}

Function _GetHostPoolCompliance {
    <#
    .SYNOPSIS
        Using the host pool group metrics, this function can determine if the host pool is: compliant, not-compliant, or needs-resources
    #>
    [CmdletBinding()]
    Param (
        [PSCustomObject]$hostPoolData,
        [Switch]$PassThru
    )

    if ($hostPoolData.available -eq $hostPoolData.needed -AND $hostPoolData.draining -eq 0 ) {
        $result = "COMPLIANT"
        $complianceState = "OPTIMAL"
        $message = ("[{0}] Host Pool is: {1}" -f $hostPoolData.hostPoolName,$result)
    }
    elseif ($hostPoolData.needed -gt $hostPoolData.sessionHosts.Count) {
        $result = "NEEDS-RESOURCES"
        $complianceState = "DEPLOY"
        $message = ("[{0}] Host Pool, {1}; deploy more session hosts to increase capacity" -f $hostPoolData.hostPoolName,$result)
    }
    else {
        $result = "NOT-COMPLIANT"
        $complianceState = "OPTIMIZE"
        $message = ("[{0}] Host Pool is: {1}" -f $hostPoolData.hostPoolName,$result)
    }
    
    Write-Verbose $message
    $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
        -Entry 'INFO' `
        -HostPoolState $result `
        -ComplianceTask 'HOST-POOL-COMPLIANCE' `
        -ComplianceState $complianceState `
        -Available $hostPoolData.available `
        -Draining $hostPoolData.draining `
        -Unavailable $hostPoolData.unavailable `
        -SessionHostCount $hostPoolData.total `
        -MaxSessions $hostPoolData.maxSessions `
        -Needed $hostPoolData.needed `
        -Sessions $hostPoolData.hostPoolSessions `
        -Load $hostPoolData.hostPoolLoad `
        -message $message
    If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry }

    $hostPoolData = $null
    Return $result
}

Function _NewHostPoolCompliancePlan {
    <#
    .SYNOPSIS
        Using the host pool group metrics, this function creates a compliance plan which is used during the optimization runbook.
    .DESCRIPTION
        This function will create a single compliance plan for a particular host pool group of session hosts. This plan should be all encompassing and will ensure the host pool group becomes compliant based on the time of day
    #>
    [CmdletBinding()]
    Param (
        [PSCustomObject]$hostPoolData,
        [Switch]$PassThru
    )

    $hostPoolScaleInfo = [PSCustomObject]@{
        RemoveDrainMode = 0
        StartVMs = 0
        DrainAndStopVMs = 0
    }

    if ($hostPoolData.needed -gt $hostPoolData.available -and $hostPoolData.needed -le ($hostPoolData.available + $hostPoolData.draining)) {
        $hostPoolScaleInfo.RemoveDrainMode = $hostPoolData.needed - $hostPoolData.available
        if ($hostPoolScaleInfo.RemoveDrainMode -lt $hostPoolData.draining) {$hostPoolScaleInfo.DrainAndStopVMs = $hostPoolData.draining - $hostPoolScaleInfo.RemoveDrainMode}
        $entryType = 'INFO'
        $message = ("AllowNewSessions: {0} | StartVMs: {1} | DrainAndStopVMs: {2}" -f $hostPoolScaleInfo.RemoveDrainMode,$hostPoolScaleInfo.StartVMs,$hostPoolScaleInfo.DrainAndStopVMs)  
    }
    elseif ($hostPoolData.needed -gt $hostPoolData.available -and $hostPoolData.needed -gt ($hostPoolData.available + $hostPoolData.draining)) {
        $hostPoolScaleInfo.RemoveDrainMode = $hostPoolData.needed - $hostPoolData.available
        if ($hostPoolScaleInfo.RemoveDrainMode -lt $hostPoolData.draining) {$hostPoolScaleInfo.DrainAndStopVMs = $hostPoolData.draining - $hostPoolScaleInfo.RemoveDrainMode}
        else {
            $hostPoolScaleInfo.RemoveDrainMode = $hostPoolData.draining
            $hostPoolScaleInfo.StartVMs = $hostPoolData.needed - ($hostPoolData.available + $hostPoolData.draining)
        }
        $entryType = 'INFO'
        $message = ("AllowNewSessions: {0} | StartVMs: {1} | DrainAndStopVMs: {2}" -f $hostPoolScaleInfo.RemoveDrainMode,$hostPoolScaleInfo.StartVMs,$hostPoolScaleInfo.DrainAndStopVMs)
    }
    elseif ($hostPoolData.needed -eq $hostPoolData.available -and $hostPoolData.draining -gt 0) {
        $hostPoolScaleInfo.DrainAndStopVMs = $hostPoolData.draining
        $entryType = 'INFO'
        $message = ("AllowNewSessions: {0} | StartVMs: {1} | DrainAndStopVMs: {2}" -f $hostPoolScaleInfo.RemoveDrainMode,$hostPoolScaleInfo.StartVMs,$hostPoolScaleInfo.DrainAndStopVMs)
    }
    elseif ($hostPoolData.needed -lt $hostPoolData.available) {
        $hostPoolScaleInfo.DrainAndStopVMs = ($hostPoolData.available - $hostPoolData.needed) + $hostPoolData.draining
        $entryType = 'INFO'
        $message = ("AllowNewSessions: {0} | StartVMs: {1} | DrainAndStopVMs: {2}" -f $hostPoolScaleInfo.RemoveDrainMode,$hostPoolScaleInfo.StartVMs,$hostPoolScaleInfo.DrainAndStopVMs)
    }
    else {
        $entryType = 'WARNING'
        $message = ("[{0}] Unable to create host pool compliance plan" -f $hostPoolName)
    }

    Write-Verbose $message
    $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
        -Entry $entryType `
        -HostPoolState 'NOT-COMPLIANT' `
        -ComplianceTask 'HOST-POOL-COMPLIANCE-PLAN' `
        -ComplianceState 'OPTIMIZE' `
        -Available $hostPoolData.available `
        -Draining $hostPoolData.draining `
        -Unavailable $hostPoolData.unavailable `
        -SessionHostCount $hostPoolData.total `
        -MaxSessions $hostPoolData.maxSessions `
        -Needed $hostPoolData.needed `
        -Sessions $hostPoolData.hostPoolSessions `
        -Load $hostPoolData.hostPoolLoad `
        -message $message
    If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry }
    $hostPoolData = $null
    return $hostPoolScaleInfo  
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
        $AzureAutomation = $true
    }
    catch { Write-Error -Exception "Azure RunAs Connection Failure" -Message "Unable to use Azure RunAs Connection" -Category "OperationStopped" -ErrorAction Stop }
}
Else {
    $AzureAutomation = $false
    Write-Output ("Azure Automation commands missing, skipping Azure RunAs Connection...")
}
#endregion

#region Create Azure Context(s)
# This runbook calls another runbook and needs to have an Azure Context for that subscription and automation account
Write-Output ("Creating Azure Context for Azure Automation")
$AzAutomationContext = Set-AzContext -Subscription $aaSubscriptionId -Debug:$false
If ($AzAutomationContext) {
    Write-Output ("Context created for: {0}" -f ($AzAutomationContext.Name -split " ")[0])
}
Else {
    Write-Output ("Azure Context not found!")
    Write-Error -Exception "Invalid Azure Context" -Message ("Unable to create an Azure Context under the {0} subscription" -f ($AzAutomationContext.Name -split " ")[0]) -Category "OperationStopped" -ErrorAction Stop
}

# This runbook can be used against more than 1 subscription and will need an Azure Context for the subscription where the AVD environment is located
Write-Output ("Connecting to Azure Subscription ({0})" -f $SubscriptionId)
$azContext = Set-AzContext -Subscription $SubscriptionId -Debug:$false
If ($azContext) { Write-Output ("Connected to: {0}" -f ($azContext.Name -split " ")[0]) }
Else {
    Write-Output ("Azure Context not found!")
    Write-Error -Exception "Invalid Azure Context" -Message ("Unable to create an Azure Context under the {0} subscription" -f ($azContext.Name -split " ")[0]) -Category "OperationStopped" -ErrorAction Stop
}
#endregion

#region Variables
# Verify the Host-Pool-Scale-Optimizer runbook is published otherwise, it may not execute as desired
$runbookState = (Get-AzAutomationRunbook -Name "AVD-AutoScale-Optimization" -ResourceGroupName $aaResourceGroupName -AutomationAccount $aaAccountName -DefaultProfile $AzAutomationContext).State
Switch ($runbookState) {
    "Published" { Write-Output ("'AVD-AutoScale-Optimization' Automation Runbook State: Published") }
    "Edit" {
        Write-Output ("'AVD-AutoScale-Optimization' Automation Runbook is still open for editing and must be published")
        Write-Error -Exception "Invalid Runbook State" -Message "Runbook is not yet published.  Publish the 'AVD-AutoScale-Optimization' runbook and try again." -Category "OperationStopped" -ErrorAction Stop
    }
    "New" {
        Write-Output ("'AVD-AutoScale-Optimization' Automation Runbook must be published after being newly created")
        Write-Error -Exception "Invalid Runbook State" -Message "Runbook is not yet published.  Publish the 'AVD-AutoScale-Optimization' runbook and try again." -Category "OperationStopped" -ErrorAction Stop
    }
    Default {
        Write-Output ("'AVD-AutoScale-Optimization' Automation Runbook not found")
        Write-Error -Exception "Invalid Runbook" -Message "Runbook was not found. Verify the runbook exists and try again." -Category "OperationStopped" -ErrorAction Stop
    }
}

$cid = [System.Guid]::NewGuid().ToString() # Used as a correlationId for both the compliance and optimization jobs and will allow for log analytic table joins
$subscriptionName = ($azContext.Name -split " ")[0]
$currentDateTime = [DateTime]::utcNow.AddHours(-$TZOffSetFromGMT) # Uses the time zone offset to get the current date and time
$startWarmUpDateTime = [DateTime]::Parse($currentDateTime.ToShortDateString() + ' ' + $startWarmUpTime)
$startPeakUsageDateTime = [DateTime]::Parse($currentDateTime.ToShortDateString() + ' ' + $startPeakUsageTime)
$endPeakUsageDateTime = [DateTime]::Parse($currentDateTime.ToShortDateString() + ' ' + $endPeakUsageTime)

If ($currentDateTime -ge $startWarmUpDateTime -and $currentDateTime -le $startPeakUsageDateTime) {
    If ($currentDateTime.DayOfWeek -eq "Saturday" -or $currentDateTime.DayOfWeek -eq "Sunday") { $timeOfDay = "OffPeak" } # Weekends are assumed to be 'OffPeak'
    Else { $timeOfDay = "WarmUp" }
}
ElseIf ($currentDateTime -ge $startPeakUsageDateTime -and $currentDateTime -le $endPeakUsageDateTime) {
    If ($currentDateTime.DayOfWeek -eq "Saturday" -or $currentDateTime.DayOfWeek -eq "Sunday") { $timeOfDay = "OffPeak" } # Weekends are assumed to be 'OffPeak'
    Else { $timeOfDay = "OnPeak" }
}
Else { $timeOfDay = "OffPeak" }
Write-Output ("Time of Day: {0}" -f $timeOfDay)
Write-Output ("CorrelationId: {0}" -f $cid)
#endregion

$hostPools = Get-AzWvdHostPool -Debug:$false | Where-Object {$_.HostPoolType -eq "Pooled" -AND $_.Tag["AVD-Environment"] -eq "PROD"}
If ($null -eq $hostPools) {
    Throw ("Failed to find any Host Pools in the {0} subscription" -f ($azContext.Name -split " ")[0])
}

# Loop through each host pool in the subscription
Foreach ($hostPool in $hostPools) {

    $hostPoolName = $hostPool.name
    $hostPoolFriendlyName = $hostpool.FriendlyName
    $hostPoolLoadType = $hostpool.LoadBalancerType
    $hostPoolResourceGroup = $hostPool.Id.Split("/")[4]
    $maxSessionLimit = $hostPool.MaxSessionLimit

    # Create a global variable for the static values used in the logging functions - this variable is splatted against the log entry function
    $Global:complianceLogParams = @{
        CorrelationId = $cid
        LogSource = $aaAccountName
        SubscriptionName = $subscriptionName
        ResourceGroup = $hostPoolResourceGroup
        HostPoolName = $hostPoolName
        TimeOfUse = $timeOfDay
    }

    If ($hostPool.Tag["WVD-Maintenance"] -eq $true) {
        $message = ("[{0} ({1})] Maintenance set to TRUE, Compliance check SKIPPED" -f $hostPoolName, $hostPoolFriendlyName)
        Write-Output $message
        $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
            -Entry 'WARNING' `
            -HostPoolState 'MAINTENANCE' `
            -ComplianceTask 'SKIPPED' `
            -ComplianceState 'UNKNOWN' `
            -message $message
        If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry }
    }
    Else {

        # If ($timeOfDay -eq "WarmUp") {
        #     If ($hostPoolLoadType -eq "BreadthFirst") {
        #         Write-Output ("[{0} ({1})] Host Pool Load Phase: {2}, updating type to 'DepthFirst'" -f $HostPoolName, $hostPoolFriendlyName, $timeOfDay)
        #         Update-AzWvdHostPool -Name $hostPoolName -ResourceGroupName $hostPoolresourceGroup -LoadBalancerType DepthFirst | Out-Null
        #     }
        #     Else { Write-Output ("[{0} ({1})] Host Pool Load Phase: {2}, already configured for 'DepthFirst'" -f $HostPoolName, $hostPoolFriendlyName, $timeOfDay) }
        # }
        # Else {
        #     If ($hostPoolLoadType -eq "DepthFirst") {
        #         Write-Output ("[{0} ({1})] Host Pool Load Phase: {2}, updating type to 'BreadthFirst'" -f $HostPoolName, $hostPoolFriendlyName, $timeOfDay)
        #         Update-AzWvdHostPool -Name $hostPoolName -ResourceGroupName $hostPoolresourceGroup -LoadBalancerType BreadthFirst | Out-Null
        #     }
        #     Else { Write-Output ("[{0} ({1})] Host Pool Load Phase: {2}, already configured for 'BreadthFirst'" -f $HostPoolName, $hostPoolFriendlyName, $timeOfDay) }
        # }

        # Collection the session host data (both AVD and VM instance data, including STATUS)
        Write-Output ("[{0} ({1})] Get Session Host Info" -f $hostPoolName, $hostPoolFriendlyName)
        $sessionHostInfo = _GetSessionHostInfo -hostPoolName $hostPoolName -resourceGroupName $hostPoolResourceGroup
        
        # Sets the minimum session hosts based on the number of groups found in the VM tags (default is 2)
        # Also looks at the percent of the total session hosts and will select a value depending
        $minimumSessionHosts = _GetMinimumSessionHosts -SessionHosts $sessionHostInfo -Plan $timeOfDay
        Write-Output ("[{0} ({1})] Get Host Pool Metrics" -f $hostPoolName, $hostPoolFriendlyName)
        $hostPoolMetrics = _GetHostPoolMetrics -hostPoolName $hostPoolName -resourceGroupName $hostPoolresourceGroup -minimumSessionHosts $minimumSessionHosts -hostPoolSessionLimit $maxSessionLimit -sessionHosts $sessionHostInfo
        
        # Validation the host pool group metrics contains data
        If ($null -eq $hostPoolMetrics) {
            Write-Output ("[{0} ({1})] Host Pool Metrics is empty" -f $hostPoolName, $hostPoolFriendlyName)
        }
        Else {
            Write-Output ("`tTotal: {1} | Avail: {2} | Drain: {3} | Unavail: {4} | Need: {5} | Load: {6}% | Sess: {7}" -f $hostPoolName, $hostPoolMetrics.total, $hostPoolMetrics.available, $hostPoolMetrics.draining, $hostPoolMetrics.unavailable, $hostPoolMetrics.needed, $hostPoolMetrics.hostPoolLoad, $hostPoolMetrics.hostPoolSessions)
            # Gets the compliance status for the host pool, based on group (A/B)
            Write-Output ("[{0} ({1})] Get Host Pool Compliance State" -f $hostPoolName,$hostPoolFriendlyName)
            $hostPoolCompliance = _GetHostPoolCompliance -hostPoolData $hostPoolMetrics
            Write-Output ("`tCompliance State: {1}" -f $hostPoolName, $hostPoolCompliance)

            If ($hostPoolCompliance -eq "NOT-COMPLIANT") {
                # Host pool is not compliant, create compliance plan based on the host pool group metrics
                Write-Output ("[{0} ({1})] Create Host Pool Compliance Plan" -f $hostPoolName,$hostPoolFriendlyName)
                $optimizeHostPool = $true
                $hostPoolScaleInfo = _NewHostPoolCompliancePlan -hostPoolData $hostPoolMetrics
                Write-Output ("`tStartVMs: {0} | RemoveDrainMode: {1} | DrainAndStopVMs: {2}" -f $hostPoolScaleInfo.StartVMs, $hostPoolScaleInfo.RemoveDrainMode, $hostPoolScaleInfo.DrainAndStopVMs)
                
                # Check automation variable to track previous optimization job runs
                $hostPoolAAVariable = Get-AzAutomationVariable -Name ("{0}-OptimizationJob" -f $hostPoolName) -AutomationAccountName $aaAccountName -ResourceGroupName $aaResourceGroupName -ErrorAction SilentlyContinue -DefaultProfile $AzAutomationContext
                If (-NOT $hostPoolAAVariable) { 
                    # Create the variable if it does not exist and store a new GUID
                    $hostPoolAAVariable = New-AzAutomationVariable -Name ("{0}-OptimizationJob" -f $hostPoolName) -Value ([Guid]::NewGuid().ToString()) -Description "AVD-AutoScale-Optimization Runbook Job Id" -Encrypted:$false -AutomationAccountName $aaAccountName -ResourceGroupName $aaResourceGroupName -DefaultProfile $AzAutomationContext
                    If ($hostPoolAAVariable) { 
                        $message = ("[{0} ({1})] Created Automation Variable for Optimization Job tracking ({2})]" -f $hostPoolName,$hostPoolFriendlyName,$hostPoolAAVariable.Name)
                        Write-Output $message
                        $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
                            -Entry 'INFO' `
                            -ComplianceTask 'OPTIMIZE-TRACKER' `
                            -ComplianceState 'CREATED' `
                            -Available $hostPoolMetrics.available `
                            -Draining $hostPoolMetrics.draining `
                            -Unavailable $hostPoolMetrics.unavailable `
                            -SessionHostCount $hostPoolMetrics.total `
                            -MaxSessions $hostPoolMetrics.maxSessions `
                            -Needed $hostPoolMetrics.needed `
                            -Sessions $hostPoolMetrics.hostPoolSessions `
                            -Load $hostPoolMetrics.hostPoolLoad `
                            -Message $message
                        If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry }
                    } # If created successfully, enable optimization to run
                    Else { 
                        $optimizeHostPool = $false
                        Write-Output ("[{0} ({1})] Unable to create Azure Automation Variable - Unable to run 'AVD-AutoScale-Optimization'" -f $hostPoolName, $hostPoolFriendlyName)
                    } # Failure to create variable prevents optimization from running
                }
                Else {
                    # Look for the automation job with the id stored in the automation variable
                    $optimizeJob = Get-AzAutomationJob -Id $hostPoolAAVariable.Value -AutomationAccountName $aaAccountName -ResourceGroupName $aaResourceGroupName -ErrorAction SilentlyContinue -DefaultProfile $AzAutomationContext
                    # If job exists, check the job status
                    If ($optimizeJob) {
                        Switch ($optimizeJob.Status) {
                            # Previous job was completed successfully, enable new optimization
                            "Completed" {
                                $message = ("[{0} ({1})] Previous optimization job completed successfully" -f $hostPoolName,$hostPoolFriendlyName)
                                Write-Output $message
                                $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
                                    -Entry 'INFO' `
                                    -ComplianceTask 'OPTIMIZE-JOB' `
                                    -ComplianceState 'COMPLETED' `
                                    -Available $hostPoolMetrics.available `
                                    -Draining $hostPoolMetrics.draining `
                                    -Unavailable $hostPoolMetrics.unavailable `
                                    -SessionHostCount $hostPoolMetrics.total `
                                    -MaxSessions $hostPoolMetrics.maxSessions `
                                    -Needed $hostPoolMetrics.needed `
                                    -Sessions $hostPoolMetrics.hostPoolSessions `
                                    -Load $hostPoolMetrics.hostPoolLoad `
                                    -Message $message
                                If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry }
                            }
                            # Previous job is still running, check how long its been running
                            "Running" {
                                $jobRunTime = [DateTime]::UtcNow.Subtract($optimizeJob.StartTime.UtcDateTime)
                                # Less than 30 minutes, the job is still valid and should continue to process
                                If ($jobRunTime.TotalMinutes -lt 30) { 
                                    $optimizeHostPool = $false
                                    $message = ("[{0} ({1})] 'AVD-AutoScale-Optimization' automation job is running, {2:N0} minutes (max: 30 minutes))" -f $hostPoolName,$hostPoolFriendlyName,$jobRunTime.TotalMinutes)
                                    Write-Output $message
                                    $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
                                        -Entry 'WARNING' `
                                        -ComplianceTask 'OPTIMIZE-JOB' `
                                        -ComplianceState 'RUNNING' `
                                        -Available $hostPoolMetrics.available `
                                        -Draining $hostPoolMetrics.draining `
                                        -Unavailable $hostPoolMetrics.unavailable `
                                        -SessionHostCount $hostPoolMetrics.total `
                                        -MaxSessions $hostPoolMetrics.maxSessions `
                                        -Needed $hostPoolMetrics.needed `
                                        -Sessions $hostPoolMetrics.hostPoolSessions `
                                        -Load $hostPoolMetrics.hostPoolLoad `
                                        -Message $message
                                    If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry }
                                }
                                # Over 30 minutes and it's likely the job is stuck. Write an error to log analytics (trigger an alert)
                                Else {
                                    $optimizeHostPool = $false
                                    $message = ("[{0} ({1})] 'AVD-AutoScale-Optimization' automation job has exceeded the maximum runtime ({2:N1} > 30 minutes)" -f $hostPoolName,$hostPoolFriendlyName,$jobRunTime.TotalMinutes)
                                    Write-Output $message
                                    $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
                                        -Entry 'ERROR' `
                                        -HostPoolState 'NOT-OPTIMIZED' `
                                        -ComplianceTask 'OPTIMIZE-JOB' `
                                        -ComplianceState 'RUNTIME-EXCEEDED' `
                                        -Available $hostPoolMetrics.available `
                                        -Draining $hostPoolMetrics.draining `
                                        -Unavailable $hostPoolMetrics.unavailable `
                                        -SessionHostCount $hostPoolMetrics.total `
                                        -MaxSessions $hostPoolMetrics.maxSessions `
                                        -Needed $hostPoolMetrics.needed `
                                        -Sessions $hostPoolMetrics.hostPoolSessions `
                                        -Load $hostPoolMetrics.hostPoolLoad `
                                        -message $message
                                    If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry }
                                }
                            }
                            Default {
                                # Previous job is not complete nor running, probably failed and can attempt another optimization
                                $message = ("[{0} ({1})] 'Host-Pool-Scale-Optimizer' automation job did not complete ({2})" -f $hostPoolName,$hostPoolFriendlyName,$optimizeJob.Status)
                                Write-Output $message
                                $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
                                    -Entry 'ERROR' `
                                    -HostPoolState 'NOT-OPTIMIZED' `
                                    -ComplianceTask 'OPTIMIZE-JOB' `
                                    -ComplianceState 'NOT-COMPLETE' `
                                    -Available $hostPoolMetrics.available `
                                    -Draining $hostPoolMetrics.draining `
                                    -Unavailable $hostPoolMetrics.unavailable `
                                    -SessionHostCount $hostPoolMetrics.total `
                                    -MaxSessions $hostPoolMetrics.maxSessions `
                                    -Needed $hostPoolMetrics.needed `
                                    -Sessions $hostPoolMetrics.hostPoolSessions `
                                    -Load $hostPoolMetrics.hostPoolLoad `
                                    -message $message
                                If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry }
                            }
                        }
                    }
                }
                
                # Check if host pool should be enabled for optimization
                If ($optimizeHostPool -AND $AzureAutomation) {
                    # Parameters for the optimization runbook
                    $runbookParams = @{
                        SubscriptionId = $SubscriptionId
                        HostPoolName = $hostPoolName
                        ResourceGroupName = $hostPoolresourceGroup
                        aaAccountName = $aaAccountName
                        metrics = $hostPoolMetrics
                        scaleInfo = $hostPoolScaleInfo
                        correlationId = $cid
                        laWorkspaceId = $laWorkspaceId
                        laWorkspaceKey = $laWorkspaceKey
                        laOptimizeLogName = "AVD_AutoScale_Optimization_CL" # Update this value to reflect the log analytics table to use for optimization logs
                    }

                    # Start the optimization runbook
                    $runbookStatus = Start-AzAutomationRunbook -Name "AVD-AutoScale-Optimization" -ResourceGroupName $aaResourceGroupName -AutomationAccountName $aaAccountName -Parameters $runbookParams -DefaultProfile $AzAutomationContext
                    If ($runbookStatus) {
                        # Successfully starting the runbook will generate a job id that is stored in the automation variable for tracking purposes
                        $aaVariable = Set-AzAutomationVariable -Name $hostPoolAAVariable.Name -Value $runbookStatus.JobId.ToString() -Encrypted $false -AutomationAccountName $aaAccountName -ResourceGroupName $aaResourceGroupName -DefaultProfile $AzAutomationContext
                        If ($aaVariable) { Write-Output ("[{0} ({1})] Successfully saved the optimization job id to: {2}" -f $hostPoolName, $hostPoolFriendlyName,$hostPoolAAVariable.Name) } # Automation variable was saved
                        Else { Write-Output ("[{0} ({1})] Failed saved the optimization job id to: {2}" -f $hostPoolName, $hostPoolFriendlyName,$hostPoolAAVariable.Name) } # Automation variable was not saved
                        $message = ("[{0} ({1})] Calling 'AVD-AutoScale-Optimization' Runbook (id: {2})" -f $hostPoolName,$hostPoolFriendlyName,$runbookStatus.JobId)
                        Write-Output $message
                        $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
                            -Entry 'INFO' `
                            -HostPoolState 'NOT-COMPLIANT' `
                            -ComplianceTask 'OPTIMIZE-RUNBOOK' `
                            -ComplianceState 'OPTIMIZE' `
                            -Available $hostPoolMetrics.available `
                            -Draining $hostPoolMetrics.draining `
                            -Unavailable $hostPoolMetrics.unavailable `
                            -SessionHostCount $hostPoolMetrics.total `
                            -MaxSessions $hostPoolMetrics.maxSessions `
                            -Needed $hostPoolMetrics.needed `
                            -Sessions $hostPoolMetrics.hostPoolSessions `
                            -Load $hostPoolMetrics.hostPoolLoad `
                            -message $message
                        If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry }
                    }
                    Else {
                        # No runbook status value indicates the runbook failed to execute, log the error (trigger alert)
                        $message = ("[{0} ({1})] 'AVD-AutoScale-Optimization' automation job did not execute" -f $hostPoolName,$hostPoolFriendlyName)
                        Write-Output $message
                        $complianceLogEntry = _NewComplianceLogEntry @complianceLogParams `
                            -Entry 'ERROR' `
                            -HostPoolState 'NOT-OPTIMIZED' `
                            -ComplianceTask 'OPTIMIZE-STATUS' `
                            -ComplianceState 'RUNBOOK-FAILED' `
                            -Available $hostPoolMetrics.available `
                            -Draining $hostPoolMetrics.draining `
                            -Unavailable $hostPoolMetrics.unavailable `
                            -SessionHostCount $hostPoolMetrics.total `
                            -MaxSessions $hostPoolMetrics.maxSessions `
                            -Needed $hostPoolMetrics.needed `
                            -Sessions $hostPoolMetrics.hostPoolSessions `
                            -Load $hostPoolMetrics.hostPoolLoad `
                            -message $message
                        If (-NOT ($PassThru)) { _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry }                           
                    }
                }
                ElseIf ($optimizeHostPool) {
                    Write-Output ("[{0} ({1})] Host Pool should be OPTIMIZED, but compliance was not executed from Azure Automation!" -f $hostPoolName, $hostPoolFriendlyName)
                }
                Else {
                    # All other host pool group states reported here to the automation job output
                    $message = ("[{0} ({1})] Host Pool State: {2}" -f $hostPoolName, $hostPoolFriendlyName,$hostPoolCompliance)
                    Write-Output $message 
                }
            }
            Else {
                # All other host pool group states reported here to the automation job output
                $message = ("[{0} ({1})] Host Pool State: {2}" -f $hostPoolName, $hostPoolFriendlyName,$hostPoolCompliance)
                Write-Output $message 
            }
        }
    }
}