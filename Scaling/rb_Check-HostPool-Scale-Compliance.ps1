<#
    .SYNOPSIS
        Runbook designed to check a Windows Virtual Desktop (v2) Host Pool compliance state.
    .DESCRIPTION
        A WVD Host Pool is compliant when the number of session hosts providing access are within a specified range based on the time of day.  If the time of day is during 'OnPeak' hours, the runbook will determine compliance based on the overall session load of the host pool.  If the host pool session load is above the high threshold, the host pool will try to 'scale-up'. If the host pool session load is below the min threshold, the host pool will try to 'scale-down'. Anything in the middle is considered 'optimal'. During 'OffPeak' times or weekends, session load is not evaluated and only raw session host counts are considered. If the host pool is 'not-compliant', the optimization runbook is called to attempt and make the host pool right sized.
    .PARAMETER subscriptionId
        Provide the subscription id where the WVD Host Pool(s) has been created.
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

Param (
    [System.String]$subscriptionId,
    [System.String]$aaAccountName,
    [System.String]$aaResourceGroupName,
    [System.String]$aaSubscriptionId,
    [System.String]$laWorkspaceId,
    [System.String]$laWorkspaceKey,
    [System.String]$laComplianceLogName,
    [System.Int32]$TZOffSetFromGMT = 4,
    [System.String]$startPeakUsageTime = "07:00",
    [System.String]$endPeakUsageTime = "20:00",
    [Int]$sessionHeadroomPercent = 30,
    [Int]$sessionMaxThreshold = 70,
    [Int]$sessionMinThreshold = 40
)

#region Helper funcitons
Function Global:_NewComplianceLogEntry {
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
        $Group = "ALL-GROUPS",
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
        sessionHostGroup = $Group
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

Function Global:_WriteLALogEntry {
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
        $logMessage
    )

    BEGIN {
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

Function _GetSessionHostInfo {
    <#
    .SYNOPSIS
        Gets all the session hosts in a Windows Virtual Desktop hostpoot and gathers WVD and VM specific information
    .DESCRIPTION
        This function is the core of this script. It collects specific information about the session hosts (WVD) and the VM (VM status) to provide a holistic view of the host pool and its ability to serve users.
    .OUTPUTS
        The output of this function is an array of custom objects. The custom object contains the following data:
            - sessionHostName (WVD)
            - vmName (VM)
            - sessionHostStatus (WVD)
            - allowNewSesssion (WVD)
            - lastHeartBeat (WVD)
            - lastUpdateTime (WVD)
            - statusTimestamp (WVD)
            - session (WVD)
            - resourceId (VM)
            - resourceGroupName (VM)
            - wvdMaintenance (VM Custom Tag)
            - wvdPostDscComplete (VM Custom Tag)
            - wvdGroup (VM Custom Tag)
            - location (VM)
            - vmStatus (VM)
    #>
    [CmdletBinding()]
    Param (
        $hostPoolName,
        $resourceGroupName
    )
    [System.Collections.ArrayList]$sessionHostInfo = @()
    $wvdshArray = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName
    $azvmArray = Get-AzVM -ResourceGroupName $resourceGroupName -Status | Group-Object Name -AsHashTable -AsString
    
    Foreach ($wvdsh in $wvdshArray) {
        $objSessionHost = @{
            sessionHostName = ($wvdsh.Name.Split("/")[-1]).ToLower()
            vmName = ($wvdsh.Name.Split("/")[-1].Split(".")[0]).ToLower()
            sessionHostStatus = ([System.String]$wvdsh.Status).ToLower()
            allowNewSession = $wvdsh.AllowNewSession
            lastHeartBeat = $wvdsh.LastHeartBeat
            lastUpdateTime = $wvdsh.LastUpdateTime
            statusTimestamp = $wvdsh.StatusTimestamp
            session = $wvdsh.Session
        }

        try {
            If ($azvmArray.Keys -contains $objSessionHost.vmName) {
                $objSessionHost.resourceId = ($azvmArray[$objSessionHost.vmName].Id).ToLower()
                $objSessionHost.resourceGroupName = ($azvmArray[$objSessionHost.vmName].ResourceGroupName).ToLower()
                $objSessionHost.wvdMaintenance = $azvmArray[$objSessionHost.vmName].Tags["WVD-Maintenance"]
                $objSessionHost.wvdPostDscComplete = $azvmArray[$objSessionHost.vmName].Tags["WVD-PostDscComplete"]
                $objSessionHost.wvdGroup = $azvmArray[$objSessionHost.vmName].Tags["WVD-Group"]
                $objSessionHost.location = ($azvmArray[$objSessionHost.vmName].location).ToLower()
                $objSessionHost.vmStatus = ($azvmArray[$objSessionHost.vmName].PowerState).ToLower()
            }
            Else {
                $objVirtualMachine = Get-AzVM -Name $objSessionHost["vmName"] -Status
                If ($objVirtualMachine.Count -eq 1) {
                    If ($objVirtualMachine.Name -contains $objSessionHost.vmName) {
                        $objSessionHost.resourceGroupName = ($objVirtualMachine.Id).ToLower()
                        $objSessionHost.resourceGroupName = ($objVirtualMachine.ResourceGroupName).ToLower()
                        $objSessionHost.wvdMaintenance = $objVirtualMachine.Tags["WVD-Maintenance"]
                        $objSessionHost.wvdPostDscComplete = $objVirtualMachine.Tags["WVD-PostDscComplete"]
                        $objSessionHost.wvdGroup = $objVirtualMachine.Tags["WVD-Group"]
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
            [Void]$sessionHostInfo.Add([PSCustomObject]$objSessionHost)
        }
        catch {
            $message = $_.Exception.Message
            $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                -Entry 'ERROR' `
                -ComplianceTask 'SESSION-HOST-INFO' `
                -ComplianceState 'UNKNOWN' `
                -Message $message
            _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
        }
    }
    $message = ("[{0}] Collected session host and virtual machine information" -f $hostPoolName)
    $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
        -Entry 'INFO' `
        -Group 'ALL-GROUPS' `
        -ComplianceTask 'SESSION-HOST-INFO' `
        -ComplianceState 'UNKNOWN' `
        -SessionHostCount $sessionHostInfo.Count `
        -Message $message
    _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry

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
        [PSCustomObject]$SessionHosts,
        $PercentOfTotalSessionHosts = 5,
        $MinimumDefaultValue = 2
    )
    $Groups = ($SessionHostInfo | Select-Object -Unique wvdGroup | Measure-Object).Count
    $minSH = [math]::Ceiling($SessionHostInfo.Count * ($PercentOfTotalSessionHosts/100)/$Groups)
    If ($minSH -lt $MinimumDefaultValue) { Return $MinimumDefaultValue }
    Else { Return $minSH }
}

Function _GetHostPoolMetrics {
    <#
    .SYNOPSIS
        Gathers counts of session hosts based on status for a given host pool
    .DESCRIPTION
        Creates a hashtable. The hashtable keys are based on the wvdGroup property (custom VM Tag) used during a WVD deployment. Each key is based on a group (i.e. A, B, etc) and the key contains the host pool metrics (number of session hosts based on status)
    #>
    [CmdletBinding()]
    Param (
        $hostPoolName,
        $resourceGroupName,
        [ValidateSet("OnPeak","OffPeak")]
        $timeOfDay = "OffPeak",
        $hostPoolSessionLimit,
        [PSCustomObject]$sessionHosts
    )

    $sessionHostsByGroup = $sessionHosts | Group-Object wvdGroup -AsHashTable -AsString

    $hostPoolMetrics = @{}
    Foreach ($Key in $sessionHostsByGroup.Keys) {

        $drainingSessionHosts = (($sessionHostsByGroup[$Key] | Where-Object {$_.AllowNewSession -eq $false -and $_.sessionHostStatus -eq "available" -and $_.wvdMaintenance -eq $false -and $_.wvdPostDscComplete -eq $true -and $_.vmStatus -eq "vm running"}) | Measure-Object).Count
        $availableSessionHosts = (($sessionHostsByGroup[$Key] | Where-Object {$_.AllowNewSession -eq $true -and $_.sessionHostStatus -eq "available" -and $_.wvdMaintenance -eq $false -and $_.wvdPostDscComplete -eq $true -and $_.vmStatus -eq "vm running"}) | Measure-Object).Count
        $unavailableSessionHosts = (($sessionHostsByGroup[$Key] | Where-Object {$_.sessionHostStatus -eq "unavailable" -or $_.wvdMaintenance -eq $true -or $_.wvdPostDscComplete -eq $false -or $_.vmStatus -ne "vm running"}) | Measure-Object).Count
        $totalSessionHosts = $sessionHostsByGroup[$Key].Count
        $maxUserSessions = ($sessionHostsByGroup[$Key].Count * $hostPoolSessionLimit)
        
        [system.Collections.ArrayList]$complianceMessages = @()
        Switch ($timeOfDay) {
            # Session method is used for 'OnPeak' usage where scaling is more precise
            "OnPeak" {
                $currentUserSessions = ($sessionHostsByGroup[$key] | Measure-Object -Property session -Sum).Sum
                # Determining Host Pool User Session Load based on Session Hosts (sessionLoad is a whole number percentage based on capacity)
                If ($currentUserSessions -eq 0 -or ($availableSessionHosts -eq 0 -and $drainingSessionHosts -eq 0)) {
                    # No sessions found or no session hosts available or draining; setting load to 0%
                    $sessionLoad = 0
                    If ($currentUserSessions -eq 0) {$message = ("[{0}] No user sessions found, session load is 0%" -f $hostPoolName)}
                    Else {$message = ("[{0}] No session hosts (available or draining) found, session load is 0%" -f $hostPoolName)}
                    
                    $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                        -Entry 'INFO' `
                        -Group $Key `
                        -ComplianceTask 'HOST-POOL-METRICS' `
                        -ComplianceState 'UNKNOWN' `
                        -Available $availableSessionHosts `
                        -Draining $drainingSessionHosts `
                        -Unavailable $unavailableSessionHosts `
                        -SessionHostCount $totalSessionHosts `
                        -MaxSessions $maxUserSessions `
                        -Sessions $currentUserSessions `
                        -Load $sessionLoad `
                        -message $message
                    [Void]$complianceMessages.Add($complianceLogEntry)
                }
                Else {
                    # Session load percentage is based on the number of available and draining session hosts and the session limit    
                    $availableSessions = $availableSessionHosts * $hostPoolSessionLimit
                    $sessionLoad = [math]::Ceiling($currentUserSessions / $availablesessions * 100)
    
                    $message = ("[{0}] Checking host pool capacity, session load is {1}%" -f $hostPoolName,$sessionLoad)
                    $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                        -Entry 'INFO' `
                        -Group $Key `
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
                    [Void]$complianceMessages.Add($complianceLogEntry)
                }
                
                # Using the sessionLoad percentage to validate if the Host Pool is above or below thresholds and recommending a number of Needed Session Hosts to be online.
                If ($sessionLoad -ge $SessionMaxThreshold) {
                    # sessionLoad is over the Max Threshold
                    $sessionHostsNeeded = [math]::Ceiling(($availableSessionHosts * $SessionHeadroomPercent)/100 + $availableSessionHosts)
                    $message = ("[{0}] Current session load has exceeded {1}%" -f $hostPoolName,$SessionMaxThreshold)
                    $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                        -Entry 'INFO' `
                        -Group $Key `
                        -ComplianceTask 'HOST-POOL-METRICS' `
                        -ComplianceState 'ABOVE-THRESHOLD' `
                        -Available $availableSessionHosts `
                        -Draining $drainingSessionHosts `
                        -Unavailable $unavailableSessionHosts `
                        -SessionHostCount $totalSessionHosts `
                        -MaxSessions $maxUserSessions `
                        -Needed $sessionHostsNeeded `
                        -Sessions $currentUserSessions `
                        -Load $sessionLoad `
                        -Message $message
                    [Void]$complianceMessages.Add($complianceLogEntry)
                }
                ElseIf ($sessionLoad -le $SessionMinThreshold) {
                    # sessionLoad is below Min Threshold
                    $sessionHostsNeeded = [math]::Ceiling($currentUserSessions / $hostPoolSessionLimit)
                    If ($minimumSessionHosts -gt $sessionHostsNeeded) {
                        # Session Hosts needed is less than the minimun Session Hosts parameter - minimum session hosts used to calculate session hosts needed
                        $message = ("[{0}] Current session load has dropped below {1}% and the minimum session hosts ({2}) are greater than the session hosts needed ({3})" -f $hostPoolName,$SessionMinThreshold,$minimumSessionHosts,$sessionHostsNeeded)
                        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                            -Entry 'INFO' `
                            -Group $Key `
                            -ComplianceTask 'HOST-POOL-METRICS' `
                            -ComplianceState 'BELOW-THRESHOLD' `
                            -Available $availableSessionHosts `
                            -Draining $drainingSessionHosts `
                            -Unavailable $unavailableSessionHosts `
                            -SessionHostCount $totalSessionHosts `
                            -MaxSessions $maxUserSessions `
                            -Needed $sessionHostsNeeded `
                            -Sessions $currentUserSessions `
                            -Load $sessionLoad `
                            -Message $message
                        [Void]$complianceMessages.Add($complianceLogEntry)
                        $sessionHostsNeeded = $minimumSessionHosts
                    }
                    Else {
                        $message = ("[{0}] Current session load has dropped below {1}%" -f $hostPoolName,$SessionMinThreshold)
                        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                            -Entry 'INFO' `
                            -Group $Key `
                            -ComplianceTask 'HOST-POOL-METRICS' `
                            -ComplianceState 'BELOW-THRESHOLD' `
                            -Available $availableSessionHosts `
                            -Draining $drainingSessionHosts `
                            -Unavailable $unavailableSessionHosts `
                            -SessionHostCount $totalSessionHosts `
                            -MaxSessions $maxUserSessions `
                            -Needed $sessionHostsNeeded `
                            -Sessions $currentUserSessions `
                            -Load $sessionLoad `
                            -Message $message
                        [Void]$complianceMessages.Add($complianceLogEntry)
                    }
                }
                Else {
                    # sessionLoad is Optimal
                    $sessionHostsNeeded = $availableSessionHosts
                    If ($minimumSessionHosts -gt $sessionHostsNeeded) {
                        # Session Hosts needed is less than the minimun Session Hosts parameter - minimum session hosts used to calculate session hosts needed
                        $message = ("[{0}] Current session load optimal and the minimum session hosts ({2}) are greater than the session hosts needed ({3})" -f $hostPoolName,$SessionMinThreshold,$minimumSessionHosts,$sessionHostsNeeded)
                        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                            -Entry 'INFO' `
                            -Group $Key `
                            -ComplianceTask 'HOST-POOL-METRICS' `
                            -ComplianceState 'BELOW-MINIMUM-HOSTS' `
                            -Available $availableSessionHosts `
                            -Draining $drainingSessionHosts `
                            -Unavailable $unavailableSessionHosts `
                            -SessionHostCount $totalSessionHosts `
                            -MaxSessions $maxUserSessions `
                            -Needed $sessionHostsNeeded `
                            -Sessions $currentUserSessions `
                            -Load $sessionLoad `
                            -Message $message
                        [Void]$complianceMessages.Add($complianceLogEntry)
                        $sessionHostsNeeded = $minimumSessionHosts
                    }
                    Else {
                        $message = ("[{0}] Current session load is optimal ({1}%)" -f $hostPoolName,$sessionLoad)
                        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                            -Entry 'INFO' `
                            -Group $Key `
                            -ComplianceTask 'HOST-POOL-METRICS' `
                            -ComplianceState 'OPTIMAL' `
                            -Available $availableSessionHosts `
                            -Draining $drainingSessionHosts `
                            -Unavailable $unavailableSessionHosts `
                            -SessionHostCount $totalSessionHosts `
                            -MaxSessions $maxUserSessions `
                            -Needed $sessionHostsNeeded `
                            -Sessions $currentUserSessions `
                            -Load $sessionLoad `
                            -Message $message
                        [Void]$complianceMessages.Add($complianceLogEntry)
                    }
                }
            }
            # SessionHost method is used for 'OffPeak' usage where scaling is flat
            "OffPeak" {
                $currentUserSessions = (Get-AzWvdUserSession -HostPoolName $hostPoolName -ResourceGroupName $resourceGroupName).Count
                $sessionLoad = 0
                # Max number of OffPeak sessions
                $maxSessionThresholdOffPeak = [math]::Ceiling((($minimumSessionHosts * $hostPoolSessionLimit) * $SessionMaxThreshold) / 100)
                If ($currentUserSessions -gt $maxSessionThresholdOffPeak) {
                    # Current sessions above max threshold for 'Off-Peak' usage
                    $sessionHostsNeeded = [math]::Ceiling(($currentUserSessions * ($sessionHeadroomPercent / 100) + $currentUserSessions) / $hostPoolSessionLimit)
                    $message = ("[{0}] Current user sessions have exceeded {1} maximum off-peak sessions" -f $hostPoolName,$maxSessionThresholdOffPeak)
                    $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                        -Entry 'INFO' `
                        -Group $Key `
                        -ComplianceTask 'HOST-POOL-METRICS' `
                        -ComplianceState 'ABOVE-THRESHOLD' `
                        -Available $availableSessionHosts `
                        -Draining $drainingSessionHosts `
                        -Unavailable $unavailableSessionHosts `
                        -SessionHostCount $totalSessionHosts `
                        -MaxSessions $maxUserSessions `
                        -Needed $sessionHostsNeeded `
                        -Sessions $currentUserSessions `
                        -Load $sessionLoad `
                        -Message $message
                    [Void]$complianceMessages.Add($complianceLogEntry)
                }
                Else {
                    # Current sessions below max threshold for 'Off-Peak' usage
                    If ($availableSessionHosts -eq $minimumSessionHosts) {
                        $sessionHostsNeeded = $availableSessionHosts
                        $message = ("[{0}] Available session hosts matches minimum session hosts" -f $hostPoolName,$maxSessionThresholdOffPeak)
                        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                            -Entry 'INFO' `
                            -Group $Key `
                            -ComplianceTask 'HOST-POOL-METRICS' `
                            -ComplianceState 'OPTIMAL' `
                            -Available $availableSessionHosts `
                            -Draining $drainingSessionHosts `
                            -Unavailable $unavailableSessionHosts `
                            -SessionHostCount $totalSessionHosts `
                            -MaxSessions $maxUserSessions `
                            -Needed $sessionHostsNeeded `
                            -Sessions $currentUserSessions `
                            -Load $sessionLoad `
                            -Message $message
                        [Void]$complianceMessages.Add($complianceLogEntry)
                    }
                    Else {
                        $sessionHostsNeeded = $minimumSessionHosts
                        $message = ("[{0}] Current user sessions below max off-peak sessions, using minimum session hosts value" -f $hostPoolName,$maxSessionThresholdOffPeak)
                        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                            -Entry 'INFO' `
                            -Group $Key `
                            -ComplianceTask 'HOST-POOL-METRICS' `
                            -ComplianceState 'BELOW-THRESHOLD' `
                            -Available $availableSessionHosts `
                            -Draining $drainingSessionHosts `
                            -Unavailable $unavailableSessionHosts `
                            -SessionHostCount $totalSessionHosts `
                            -MaxSessions $maxUserSessions `
                            -Needed $sessionHostsNeeded `
                            -Sessions $currentUserSessions `
                            -Load $sessionLoad `
                            -Message $message
                        [Void]$complianceMessages.Add($complianceLogEntry)
                    }
                }
            }
        }
    
        _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceMessages
    
        $metrics = [PSCustomObject]@{
            sessionHosts = $sessionHostsByGroup[$Key]
            draining = $drainingSessionHosts
            available = $availableSessionHosts
            unavailable = $unavailableSessionHosts
            total = $totalSessionHosts
            needed = $sessionHostsNeeded
            maxSessions = $maxUserSessions
            hostPoolSessions = $currentUserSessions
            hostPoolLoad = $sessionLoad
        }
        $hostPoolMetrics.Add($Key,$metrics)
    }
    
    Return $hostPoolMetrics
}

Function _GetHostPoolCompliance {
    <#
    .SYNOPSIS
        Using the host pool group metrics, this function can determine if the host pool is: compliant, not-compliant, or needs-resources
    #>
    [CmdletBinding()]
    Param ([PSCustomObject]$hostPoolData)

    if ($hostPoolData.available -eq $hostPoolData.needed -and $hostPoolData.draining -eq 0 ) {
        $result = "COMPLIANT"
        $message = ("[{0}] Host Pool Group {1} is: {2}" -f $hostPoolName,$Group,$result)
        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
            -Entry 'INFO' `
            -HostPoolState $result `
            -Group $Group `
            -ComplianceTask 'HOST-POOL-COMPLIANCE' `
            -ComplianceState 'OPTIMAL' `
            -Available $hostPoolData.available `
            -Draining $hostPoolData.draining `
            -Unavailable $hostPoolData.unavailable `
            -SessionHostCount $hostPoolData.total `
            -MaxSessions $hostPoolData.maxSessions `
            -Needed $hostPoolData.needed `
            -Sessions $hostPoolData.hostPoolSessions `
            -Load $hostPoolData.hostPoolLoad `
            -message $message
        _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry 
        $hostPoolData = $null
        Return $result
    }
    elseif ($hostPoolData.needed -gt $hostPoolData.sessionHosts.Count) {
        $result = "NEEDS-RESOURCES"
        $message = ("[{0}] Host Pool Group {1} is out of session hosts; deploy more session hosts to increase capacity" -f $hostPoolName,$Group)
        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
            -Entry 'INFO' `
            -HostPoolState $result `
            -Group $Group `
            -ComplianceTask 'HOST-POOL-COMPLIANCE' `
            -ComplianceState 'DEPLOY' `
            -Available $hostPoolData.available `
            -Draining $hostPoolData.draining `
            -Unavailable $hostPoolData.unavailable `
            -SessionHostCount $hostPoolData.total `
            -MaxSessions $hostPoolData.maxSessions `
            -Needed $hostPoolData.needed `
            -Sessions $hostPoolData.hostPoolSessions `
            -Load $hostPoolData.hostPoolLoad `
            -message $message
        _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry 
        $hostPoolData = $null
        Return $result
    }
    else {
        $result = "NOT-COMPLIANT"
        $message = ("[{0}] Host Pool Group {1} is: {2}" -f $hostPoolName,$Group,$result)
        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
            -Entry 'INFO' `
            -HostPoolState $result `
            -Group $Group `
            -ComplianceTask 'HOST-POOL-COMPLIANCE' `
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
        _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
        $hostPoolData = $null
        Return $result
    }
}

Function _NewHostPoolCompliancePlan {
    <#
    .SYNOPSIS
        Using the host pool group metrics, this function creates a compliance plan which is used during the optimization runbook.
    .DESCRIPTION
        This function will create a single compliance plan for a particular host pool group of session hosts. This plan should be all encompassing and will ensure the host pool group becomes compliant based on the time of day
    #>
    [CmdletBinding()]
    Param ([PSCustomObject]$hostPoolData)

    $hostPoolScaleInfo = [PSCustomObject]@{
        RemoveDrainMode = 0
        StartVMs = 0
        DrainAndStopVMs = 0
    }

    if ($hostPoolData.needed -gt $hostPoolData.available -and $hostPoolData.needed -le ($hostPoolData.available + $hostPoolData.draining)) {
        $hostPoolScaleInfo.RemoveDrainMode = $hostPoolData.needed - $hostPoolData.available
        if ($hostPoolScaleInfo.RemoveDrainMode -lt $hostPoolData.draining) {$hostPoolScaleInfo.DrainAndStopVMs = $hostPoolData.draining - $hostPoolScaleInfo.RemoveDrainMode}

        $message = ("AllowNewSessions: {0} | StartVMs: {1} | DrainAndStopVMs: {2}" -f $hostPoolScaleInfo.RemoveDrainMode,$hostPoolScaleInfo.StartVMs,$hostPoolScaleInfo.DrainAndStopVMs)
        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
            -Entry 'INFO' `
            -HostPoolState 'NOT-COMPLIANT' `
            -Group $Group `
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
        _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
        $hostPoolData = $null
        return $hostPoolScaleInfo    
    }
    elseif ($hostPoolData.needed -gt $hostPoolData.available -and $hostPoolData.needed -gt ($hostPoolData.available + $hostPoolData.draining)) {
        $hostPoolScaleInfo.RemoveDrainMode = $hostPoolData.needed - $hostPoolData.available
        if ($hostPoolScaleInfo.RemoveDrainMode -lt $hostPoolData.draining) {$hostPoolScaleInfo.DrainAndStopVMs = $hostPoolData.draining - $hostPoolScaleInfo.RemoveDrainMode}
        else {
            $hostPoolScaleInfo.RemoveDrainMode = $hostPoolData.draining
            $hostPoolScaleInfo.StartVMs = $hostPoolData.needed - ($hostPoolData.available + $hostPoolData.draining)
        }

        $message = ("AllowNewSessions: {0} | StartVMs: {1} | DrainAndStopVMs: {2}" -f $hostPoolScaleInfo.RemoveDrainMode,$hostPoolScaleInfo.StartVMs,$hostPoolScaleInfo.DrainAndStopVMs)
        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
            -Entry 'INFO' `
            -HostPoolState 'NOT-COMPLIANT' `
            -Group $Group `
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
        _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
        $hostPoolData = $null
        Return $hostPoolScaleInfo
    }
    elseif ($hostPoolData.needed -eq $hostPoolData.available -and $hostPoolData.draining -gt 0) {
        $hostPoolScaleInfo.DrainAndStopVMs = $hostPoolData.draining

        $message = ("AllowNewSessions: {0} | StartVMs: {1} | DrainAndStopVMs: {2}" -f $hostPoolScaleInfo.RemoveDrainMode,$hostPoolScaleInfo.StartVMs,$hostPoolScaleInfo.DrainAndStopVMs)
        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
            -Entry 'INFO' `
            -HostPoolState 'NOT-COMPLIANT' `
            -Group $Group `
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
        _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
        $hostPoolData = $null
        return $hostPoolScaleInfo
    }
    elseif ($hostPoolData.needed -lt $hostPoolData.available) {
        $hostPoolScaleInfo.DrainAndStopVMs = ($hostPoolData.available - $hostPoolData.needed) + $hostPoolData.draining

        $message = ("AllowNewSessions: {0} | StartVMs: {1} | DrainAndStopVMs: {2}" -f $hostPoolScaleInfo.RemoveDrainMode,$hostPoolScaleInfo.StartVMs,$hostPoolScaleInfo.DrainAndStopVMs)
        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
            -Entry 'INFO' `
            -HostPoolState 'NOT-COMPLIANT' `
            -Group $Group `
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
        _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
        $hostPoolData = $null
        return $hostPoolScaleInfo
    }
    else {
        $message = ("[{0}] Unable to create host pool compliance plan" -f $hostPoolName)
        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
            -Entry 'WARNING' `
            -HostPoolState 'NOT-COMPLIANT' `
            -Group $Group `
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
        _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
        $hostPoolData = $null
        return $hostPoolScaleInfo
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
    catch { Write-Error -Exception "Azure RunAs Connection Failure" -Message "Unable to use Azure RunAs Connection" -Category "OperationStopped" -ErrorAction Stop }
}
Else { Write-Output ("Azure Automation commands missing, skipping Azure RunAs Connection...") }
#endregion

#region Create Azure Context(s)
# This runbook calls another runbook and needs to have an Azure Context for that subscription and automation account
Write-Output ("Creating Azure Context for Azure Automation")
$AzAutomationContext = Set-AzContext -Subscription $aaSubscriptionId
If ($AzAutomationContext) {
    Write-Output ("Context created for: {0}" -f ($AzAutomationContext.Name -split " ")[0])
}
Else {
    Write-Output ("Azure Context not found!")
    Write-Error -Exception "Invalid Azure Context" -Message ("Unable to create an Azure Context under the {0} subscription" -f ($AzAutomationContext.Name -split " ")[0]) -Category "OperationStopped" -ErrorAction Stop
}

# This runbook can be used against more than 1 subscription and will need an Azure Context for the subscription where the WVD environment is located
Write-Output ("Connecting to Azure Subscription ({0})" -f $SubscriptionId)
$azContext = Set-AzContext -Subscription $SubscriptionId
If ($azContext) { Write-Output ("Connected to: {0}" -f ($azContext.Name -split " ")[0]) }
Else {
    Write-Output ("Azure Context not found!")
    Write-Error -Exception "Invalid Azure Context" -Message ("Unable to create an Azure Context under the {0} subscription" -f ($azContext.Name -split " ")[0]) -Category "OperationStopped" -ErrorAction Stop
}
#endregion

#region Variables
# Verify the Host-Pool-Scale-Optimizer runbook is published otherwise, it may not execute as desired
$runbookState = (Get-AzAutomationRunbook -Name "HostPool-Scale-Optimizer" -ResourceGroupName $aaResourceGroupName -AutomationAccount $aaAccountName -DefaultProfile $AzAutomationContext).State 
Switch ($runbookState) {
    "Published" { Write-Output ("'HostPool-Scale-Optimizer' Automation Runbook State: Published") }
    "Edit" {
        Write-Output ("'HostPool-Scale-Optimizer' Automation Runbook is still open for editing and must be published")
        Write-Error -Exception "Invalid Runbook State" -Message "Runbook is not yet published.  Publish the 'HostPool-Scale-Optimizer' runbook and try again." -Category "OperationStopped" -ErrorAction Stop
    }
    "New" {
        Write-Output ("'HostPool-Scale-Optimizer' Automation Runbook must be published after being newly created")
        Write-Error -Exception "Invalid Runbook State" -Message "Runbook is not yet published.  Publish the 'HostPool-Scale-Optimizer' runbook and try again." -Category "OperationStopped" -ErrorAction Stop
    }
    Default {
        Write-Output ("'HostPool-Scale-Optimizer' Automation Runbook not found")
        Write-Error -Exception "Invalid Runbook" -Message "Runbook was not found. Verify the runbook exists and try again." -Category "OperationStopped" -ErrorAction Stop
    }
}

$cid = [System.Guid]::NewGuid().ToString() # Used as a correlationId for both the compliance and optimization jobs and will allow for log analytic table joins
$subscriptionName = ($azContext.Name -split " ")[0]
$currentDateTime = [DateTime]::utcNow.AddHours(-$TZOffSetFromGMT) # Uses the time zone offset to get the current date and time
$startPeakUsageDateTime = [DateTime]::Parse($currentDateTime.ToShortDateString() + ' ' + $startPeakUsageTime)
$endPeakUsageDateTime = [DateTime]::Parse($currentDateTime.ToShortDateString() + ' ' + $endPeakUsageTime)

If ($currentDateTime -ge $startPeakUsageDateTime -and $currentDateTime -le $endPeakUsageDateTime) {
    If ($currentDateTime.DayOfWeek -eq "Saturday" -or $currentDateTime.DayOfWeek -eq "Sunday") { $timeOfDay = "OffPeak" } # Weekends are assumed to be 'OffPeak'
    Else { $timeOfDay = "OnPeak" }
}
Else { $timeOfDay = "OffPeak" }
Write-Output ("Time of Day: {0}" -f $timeOfDay)
Write-Output ("CorrelationId: {0}" -f $cid)
#endregion

$hostPools = Get-AzWvdHostPool
If ($null -eq $hostPools) {
    Throw ("Failed to find any Host Pools in the {0} subscription" -f ($azContext.Name -split " ")[0])
}

# Loop through each host pool in the subscription
Foreach ($hostPool in $hostPools) {

    $hostPoolName = $hostPool.name
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
        $message = ("[{0}] Maintenance set to TRUE, Compliance check SKIPPED" -f $hostPoolName)
        Write-Output $message
        $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
            -Entry 'WARNING' `
            -HostPoolState 'MAINTENANCE' `
            -ComplianceTask 'SKIPPED' `
            -ComplianceState 'UNKNOWN' `
            -message $message
        _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
    }
    Else {
        # Collection the session host data (both WVD and VM instance data, including STATUS)
        Write-Output ("[{0}] Get Session Host Info" -f $hostPoolName)
        $sessionHostInfo = _GetSessionHostInfo -hostPoolName $hostPoolName -resourceGroupName $hostPoolResourceGroup
        
        # Sets the minimum session hosts based on the number of groups found in the VM tags (default is 2)
        # Also looks at the percent of the total session hosts and will select a value depending
        $minimumSessionHosts = _GetMinimumSessionHosts -SessionHosts $sessionHostInfo -PercentOfTotalSessionHosts 5 -MinimumDefaultValue 2
        Write-Output ("[{0}] Get Host Pool Metrics" -f $hostPoolName)
        $hostPoolMetrics = _GetHostPoolMetrics -hostPoolName $hostPoolName -resourceGroupName $hostPoolResourceGroup -timeOfDay $timeOfDay -sessionHosts $sessionHostInfo -hostPoolSessionLimit $maxSessionLimit
        Foreach ($Group in $hostPoolMetrics.Keys) {
            # Check automation variable to track previous optimization job runs
            $hostPoolAAVariable = Get-AzAutomationVariable -Name ("{0}-OptimizationJob-{1}" -f $hostPoolName,$Group) -AutomationAccountName $aaAccountName -ResourceGroupName $aaResourceGroupName -ErrorAction SilentlyContinue -DefaultProfile $AzAutomationContext
            If (-NOT $hostPoolAAVariable) { 
                # Create the variable if it does not exist and store a new GUID
                $hostPoolAAVariable = New-AzAutomationVariable -Name ("{0}-OptimizationJob-{1}" -f $hostPoolName,$Group) -Value ([Guid]::NewGuid().ToString()) -Description "HostPool-Scale-Optimizer Runbook Job Id" -Encrypted:$false -AutomationAccountName $aaAccountName -ResourceGroupName $aaResourceGroupName -DefaultProfile $AzAutomationContext
                If ($hostPoolAAVariable) { 
                    $optimizeHostPool = $true
                    $message = ("[{0}] Created Automation Variable for Optimization Job tracking ({1}]" -f $hostPoolName,$hostPoolAAVariable.Name)
                    Write-Output $message
                    $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                        -Entry 'INFO' `
                        -ComplianceTask 'OPTIMIZE-TRACKER' `
                        -ComplianceState 'CREATED' `
                        -Group $Group `
                        -Available $hostPoolMetrics[$Group].available `
                        -Draining $hostPoolMetrics[$Group].draining `
                        -Unavailable $hostPoolMetrics[$Group].unavailable `
                        -SessionHostCount $hostPoolMetrics[$Group].total `
                        -MaxSessions $hostPoolMetrics[$Group].maxSessions `
                        -Needed $hostPoolMetrics[$Group].needed `
                        -Sessions $hostPoolMetrics[$Group].hostPoolSessions `
                        -Load $hostPoolMetrics[$Group].hostPoolLoad `
                        -Message $message
                    _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
                } # If created successfully, enable optimization to run
                Else { 
                    $optimizeHostPool = $false
                    Write-Output ("[Group-{0}] Unable to create Azure Automation Variable - Unable to run 'HostPool-Scale-Optimizer'" -f $Group)
                } # Failure to create variable prevents optimization from running
            }
            Else {
                $optimizeHostPool = $false
                # Look for the automation job with the id stored in the automation variable
                $optimizeJob = Get-AzAutomationJob -Id $hostPoolAAVariable.Value -AutomationAccountName $aaAccountName -ResourceGroupName $aaResourceGroupName -ErrorAction SilentlyContinue -DefaultProfile $AzAutomationContext
                # If job exists, check the job status
                If ($optimizeJob) {
                    Switch ($optimizeJob.Status) {
                        # Previous job was completed successfully, enable new optimization
                        "Completed" {
                            $optimizeHostPool = $true
                            $message = ("[Group-{0}] Previous optimization job completed successfully" -f $Group)
                            Write-Output $message
                            $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                                -Entry 'INFO' `
                                -ComplianceTask 'OPTIMIZE-JOB' `
                                -ComplianceState 'COMPLETED' `
                                -Group $Group `
                                -Available $hostPoolMetrics[$Group].available `
                                -Draining $hostPoolMetrics[$Group].draining `
                                -Unavailable $hostPoolMetrics[$Group].unavailable `
                                -SessionHostCount $hostPoolMetrics[$Group].total `
                                -MaxSessions $hostPoolMetrics[$Group].maxSessions `
                                -Needed $hostPoolMetrics[$Group].needed `
                                -Sessions $hostPoolMetrics[$Group].hostPoolSessions `
                                -Load $hostPoolMetrics[$Group].hostPoolLoad `
                                -Message $message
                            _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
                        }
                        # Previous job is still running, check how long its been running
                        "Running" {
                            $jobRunTime = [DateTime]::UtcNow.Subtract($optimizeJob.StartTime.UtcDateTime)
                            # Less than 30 minutes, the job is still valid and should continue to process
                            If ($jobRunTime.TotalMinutes -lt 30) { 
                                $optimizeHostPool = $false
                                $message = ("[Group-{0}] 'HostPool-Scale-Optimizer' automation job is running, {1:N0} minutes (max: 30 minutes))" -f $Group,$jobRunTime.TotalMinutes)
                                Write-Output $message
                                $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                                    -Entry 'WARNING' `
                                    -ComplianceTask 'OPTIMIZE-JOB' `
                                    -ComplianceState 'RUNNING' `
                                    -Group $Group `
                                    -Available $hostPoolMetrics[$Group].available `
                                    -Draining $hostPoolMetrics[$Group].draining `
                                    -Unavailable $hostPoolMetrics[$Group].unavailable `
                                    -SessionHostCount $hostPoolMetrics[$Group].total `
                                    -MaxSessions $hostPoolMetrics[$Group].maxSessions `
                                    -Needed $hostPoolMetrics[$Group].needed `
                                    -Sessions $hostPoolMetrics[$Group].hostPoolSessions `
                                    -Load $hostPoolMetrics[$Group].hostPoolLoad `
                                    -Message $message
                                _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
                            }
                            # Over 30 minutes and it's likely the job is stuck. Write an error to log analytics (trigger an alert)
                            Else {
                                $message = ("[Group-{0}] 'HostPool-Scale-Optimizer' automation job has exceeded the maximum runtime ({1:N1} > 30 minutes)" -f $Group,$jobRunTime.TotalMinutes)
                                Write-Output $message
                                $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                                    -Entry 'ERROR' `
                                    -HostPoolState 'NOT-OPTIMIZED' `
                                    -ComplianceTask 'OPTIMIZE-JOB' `
                                    -ComplianceState 'RUNTIME-EXCEEDED' `
                                    -Group $Group `
                                    -Available $hostPoolMetrics[$Group].available `
                                    -Draining $hostPoolMetrics[$Group].draining `
                                    -Unavailable $hostPoolMetrics[$Group].unavailable `
                                    -SessionHostCount $hostPoolMetrics[$Group].total `
                                    -MaxSessions $hostPoolMetrics[$Group].maxSessions `
                                    -Needed $hostPoolMetrics[$Group].needed `
                                    -Sessions $hostPoolMetrics[$Group].hostPoolSessions `
                                    -Load $hostPoolMetrics[$Group].hostPoolLoad `
                                    -message $message
                                _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
                            }
                        }
                        Default {
                            # Previous job is not complete nor running, probably failed and can attempt another optimization
                            $optimizeHostPool = $true
                            $message = ("[Group-{0}] 'Host-Pool-Scale-Optimizer' automation job did not complete ({1})" -f $Group,$optimizeJob.Status)
                            Write-Output $message
                            $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                                -Entry 'ERROR' `
                                -HostPoolState 'NOT-OPTIMIZED' `
                                -ComplianceTask 'OPTIMIZE-JOB' `
                                -ComplianceState 'NOT-COMPLETE' `
                                -Group $Group `
                                -Available $hostPoolMetrics[$Group].available `
                                -Draining $hostPoolMetrics[$Group].draining `
                                -Unavailable $hostPoolMetrics[$Group].unavailable `
                                -SessionHostCount $hostPoolMetrics[$Group].total `
                                -MaxSessions $hostPoolMetrics[$Group].maxSessions `
                                -Needed $hostPoolMetrics[$Group].needed `
                                -Sessions $hostPoolMetrics[$Group].hostPoolSessions `
                                -Load $hostPoolMetrics[$Group].hostPoolLoad `
                                -message $message
                            _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
                        }
                    }
                }
                # If no previous optimization run, enable optimizer to run
                Else { $optimizeHostPool = $true }
            }

            # Check if host pool should be enabled for optimization
            If ($optimizeHostPool) {
                # Gets the compliance status for the host pool, based on group (A/B)
                Write-Output ("[Group-{0}] Get Host Pool Compliance State ({1})" -f $Group,$hostPoolName)
                $hostPoolCompliance = _GetHostPoolCompliance -hostPoolData $hostPoolMetrics[$Group]
            
                If ($hostPoolCompliance -eq "NOT-COMPLIANT") {
                    # Host pool is not compliant, create compliance plan based on the host pool group metrics
                    $hostPoolScaleInfo = _NewHostPoolCompliancePlan -hostPoolData $hostPoolMetrics[$Group]
                    
                    # Parameters for the optimization runbook
                    $runbookParams = @{
                        SubscriptionId = $SubscriptionId
                        HostPoolName = $hostPoolName
                        ResourceGroupName = $hostPoolresourceGroup
                        aaAccountName = $aaAccountName
                        metrics = $hostPoolMetrics[$Group]
                        sessionHostGroup = $Group
                        scaleInfo = $hostPoolScaleInfo
                        correlationId = $cid
                        laWorkspaceId = $laWorkspaceId
                        laWorkspaceKey = $laWorkspaceKey
                        laOptimizeLogName = "WVD_HostPoolOptimizationLog_CL" # Update this value to reflect the log analytics table to use for optimization logs
                    }

                    # Validation the host pool group metrics contains data
                    If ($null -eq $hostPoolMetrics[$Group]) {
                        Write-Output ("[{0}] Host Pool Metrics is empty" -f $Group)
                    }
                    Else {
                        # Start the optimization runbook
                        $runbookStatus = Start-AzAutomationRunbook -Name "HostPool-Scale-Optimizer" -ResourceGroupName $aaResourceGroupName -AutomationAccountName $aaAccountName -Parameters $runbookParams -DefaultProfile $AzAutomationContext
                        If ($runbookStatus) {
                            # Successfully starting the runbook will generate a job id that is stored in the automation variable for tracking purposes
                            $aaVariable = Set-AzAutomationVariable -Name $hostPoolAAVariable.Name -Value $runbookStatus.JobId.ToString() -Encrypted $false -AutomationAccountName $aaAccountName -ResourceGroupName $aaResourceGroupName -DefaultProfile $AzAutomationContext
                            If ($aaVariable) { Write-Output ("[Group-{0}] Successfully saved the optimization job id to: {1}" -f $Group,$hostPoolAAVariable.Name) } # Automation variable was saved
                            Else { Write-Output ("[Group-{0}] Failed saved the optimization job id to: {1}" -f $Group,$hostPoolAAVariable.Name) } # Automation variable was not saved
                            $message = ("[Group-{0}] Calling 'HostPool-Scale-Optimizer' Runbook (id: {1})" -f $Group,$runbookStatus.JobId)
                            Write-Output $message
                            $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                                -Entry 'INFO' `
                                -HostPoolState 'NOT-COMPLIANT' `
                                -Group $Group `
                                -ComplianceTask 'OPTIMIZE-RUNBOOK' `
                                -ComplianceState 'OPTIMIZE' `
                                -Available $hostPoolMetrics[$Group].available `
                                -Draining $hostPoolMetrics[$Group].draining `
                                -Unavailable $hostPoolMetrics[$Group].unavailable `
                                -SessionHostCount $hostPoolMetrics[$Group].total `
                                -MaxSessions $hostPoolMetrics[$Group].maxSessions `
                                -Needed $hostPoolMetrics[$Group].needed `
                                -Sessions $hostPoolMetrics[$Group].hostPoolSessions `
                                -Load $hostPoolMetrics[$Group].hostPoolLoad `
                                -message $message
                            _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry
                        }
                        Else {
                            # No runbook status value indicates the runbook failed to execute, log the error (trigger alert)
                            $message = ("[Group-{0}] 'HostPool-Scale-Optimizer' automation job did not execute" -f $Group)
                            Write-Output $message
                            $complianceLogEntry = Global:_NewComplianceLogEntry @complianceLogParams `
                                -Entry 'ERROR' `
                                -HostPoolState 'NOT-OPTIMIZED' `
                                -ComplianceTask 'OPTIMIZE-STATUS' `
                                -ComplianceState 'RUNBOOK-FAILED' `
                                -Available $hostPoolMetrics[$Group].available `
                                -Draining $hostPoolMetrics[$Group].draining `
                                -Unavailable $hostPoolMetrics[$Group].unavailable `
                                -SessionHostCount $hostPoolMetrics[$Group].total `
                                -MaxSessions $hostPoolMetrics[$Group].maxSessions `
                                -Needed $hostPoolMetrics[$Group].needed `
                                -Sessions $hostPoolMetrics[$Group].hostPoolSessions `
                                -Load $hostPoolMetrics[$Group].hostPoolLoad `
                                -message $message
                            _WriteLALogEntry -customerId $laWorkspaceId -sharedKey $laWorkspaceKey -logName $laComplianceLogName -logMessage $complianceLogEntry                                
                        }
                    }
                }
                Else {
                    # All other host pool group states reported here to the automation job output
                    $message = ("[Group-{0}] Host Pool State: {1}" -f $Group,$hostPoolCompliance)
                    Write-Output $message 
                }
            }
        }
    }
}