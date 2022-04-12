# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format.
$currentUTCtime = (Get-Date).ToUniversalTime()
$subscriptionName = "##ENTER-YOUR-SUB-NAME-HERE##"

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"

Function Create-AccessToken {
    param($resourceURI)

    If ($null -eq $env:MSI_ENDPOINT) {
        $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
        if(!$azProfile.Accounts.Count) { Write-Error "Ensure you have logged in before calling this function." }
        $azContext = Get-AzContext
        $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azProfile)
        $token = $profileClient.AcquireAccessToken($azContext.Tenant.TenantId)
        Return $token.AccessToken
    }
    Else {
        $tokenAuthURI = $env:MSI_ENDPOINT + "?resource=$resourceURI&api-version=2017-09-01"
        $headers =  @{'Secret'="$env:MSI_SECRET"}
        try {
            $tokenResponse = Invoke-RestMethod -Method Get -header $headers -Uri $tokenAuthURI -ErrorAction:stop
            return $tokenResponse.access_token
        }
        catch {
            write-error "Unable to retrieve access token $error"
            exit 1
        }
    }
}

Function Query-Azure {
    param($query,$accesstoken)

    $url = ("https://management.azure.com/{0}" -f $query)
    $headers = @{'Authorization' = "Bearer $accessToken"}
    
    try {
        $response = Invoke-RestMethod -Method 'Get' -Uri $url -Headers $headers -ErrorAction:stop
        Return $response
    }
    catch { write-error "Unable to query Azure RestAPI: $error" }
}

Function DimensionSpliter {
    param($dimensiongroup)

    $dims = $dimensiongroup.split(";")
    [System.Collections.Generic.List[System.Object]]$dimobject = @()
    foreach ($dim in $dims) {
        $obj = [pscustomobject]@{
	        name = $dim.split(":")[0]
	        value = $dim.split(":")[1]
        }
        $dimobject.Add($obj)
    }
    return $dimobject
}

Function Calculate-Metric {
    param($metric,$sessions,$hosts,$vms,$hostpool)

    $dimvalues = DimensionSpliter $metric.Dimensions | Foreach-Object {$_.Value}

    try { [int]$imetricresult = Invoke-Command -Scriptblock $metric.Query }
    catch {
        Write-Warning ("Metric query failed for: [{0}] - {1}" -f $metric.Namespace,$metric.Metric)
        Write-Warning ("{0}" -f $_.exception.message)
        return $False
    }

    $metricdata = [pscustomobject]@{
        dimValues = $dimvalues
        min = $imetricresult
        max = $imetricresult
        sum = $imetricresult
        count = 1
    }
    return $metricdata
}

Function POST-CustomMetric{
    param($custommetricjson,$accesstoken,$targetresourceid,$region)

    $url = "https://$region.monitoring.azure.com$targetresourceid/metrics"
    $headers = @{'Authorization' = "Bearer $accessToken"
    'Content-Type' = "application/json"}
    try { $metricapiresponse = Invoke-RestMethod -Method 'Post' -Uri $url -Headers $headers -body $custommetricjson -ErrorAction:stop }
    catch {
        write-warning "Unable POST metric $error"
        return $false
    }
    return $true
}

Function Publish-Metric{
    param($metric,$sessions,$hosts,$vms,$hostpool,$azmontoken,$targetresourceid,$region)
    
    $dimnames = DimensionSpliter $metric.Dimensions | Select-Object -ExpandProperty Name

    $series = [System.Collections.Generic.List[System.Object]]@()
    $metricresult = Calculate-Metric $metric $sessions $hosts $vms $hostpool
    
    If($metricresult -eq $False) { return $False }
    Else { $series.Add($metricresult) }

    $custommetric = [PSCustomObject]@{
        time = (Get-Date -Format 'o')
        data = [PSCustomObject]@{
            baseData = [PSCustomObject]@{
                metric = $metric.metric
                namespace = $metric.namespace
                dimNames = $dimnames
                series = $series
            }
        }
    }

    $custommetricjson = $custommetric | convertto-json -depth 10 -compress
    write-output ("Publishing to Azure Monitor for Namespace:{0} Metric:{1}" -f $metric.namespace,$metric.metric)
    $Postresult = POST-CustomMetric $custommetricjson $azmontoken $targetresourceid $region 
    return $Postresult
}

# URL(s) for creating access tokens
$WVDResourceURI = "https://management.core.windows.net/"
$AZMonResourceURI = "https://monitoring.azure.com/"


Write-Output ("Creating Access Tokens for Azure and Azure Monitor")
$token = Create-AccessToken -resourceURI $WVDResourceURI
$azmontoken = Create-AccessToken -resourceURI $AZMonResourceURI

Write-Output ("Collecting WVD Azure Subscriptions")
$subscriptionsQuery = "/subscriptions?api-version=2016-06-01"
$subscriptions = (Query-Azure $subscriptionsQuery $token).Value.Where{$_.displayName -eq $subscriptionName}

foreach ($subscription in $subscriptions) {
    Write-Output ("Working on '{0}' Subscription Resources" -f $subscription.displayName)
    $subscriptionid = $subscription.subscriptionid 
    $resourceGroupQuery = ("/subscriptions/{0}/resourcegroups/?api-version=2019-10-01" -f $subscriptionid)
    $resourceGroups = (Query-Azure $resourceGroupQuery $token).Value.Where{$_.Name -match "POOL-RG"}
    Write-Output ("Found {0} Host Pool Resource Groups in '{1}'" -f $resourceGroups.Count,$subscription.displayName)

    $logAnalyticsQuery = ("/subscriptions/{0}/providers/Microsoft.OperationalInsights/workspaces?api-version=2015-11-01-preview" -f $subscriptionid)
    $logAnalyticsWorkspace = (Query-Azure $logAnalyticsQuery $token).Value.Where{$_.Tags.'WVD-Function' -eq "PROD"}
    If ($logAnalyticsWorkspace.Count -gt 1) {
        Write-Warning ("Found {0} Log Analytics Workspaces in the {1} Subscription" -f $logAnalyticsWorkspace.Count,$subscription.displayName)
        Write-Warning ("Review the Azure Query and ensure only 1 Log Analytics Workspace is returned")
        Exit 1
    }
    Else {
        $workspaceId = $logAnalyticsWorkspace.Id
        $workspaceRegion = $logAnalyticsWorkspace.Location
        $workspaceName = $logAnalyticsWorkspace.Name
    }
    
    foreach($resourceGroup in $resourceGroups) {
        Write-Output ("Working on '{0}' Resources" -f $resourceGroup.Name)
        $resourceGroupName = $resourceGroup.Name
        $wvdapi = '2019-12-10-preview'
        $hostPoolsQuery = ("/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.DesktopVirtualization/hostPools?api-version={2}" -f $subscriptionid,$resourceGroupName,$wvdapi)
        $hostPools = (Query-Azure $hostPoolsQuery $token).Value
        
        If ($hostPools.Count -gt 0) {
            Write-Output ("Found {0} Host Pool(s) in {1} Resource Group" -f $hostPools.Count,$resourceGroupName)
        
            foreach ($hostPool in  $hostPools) {
                Write-Output ("Working on '{0}' Resources" -f $hostPool.Name)
                $poolName = $hostPool.Name

                Write-Output ("Querying Azure for WVD Resource data (Virtual Machines, Session Hosts, Sessions)")
                $sessionsquery = ("/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.DesktopVirtualization/hostPools/{2}/userSessions?api-version={3}" -f $subscriptionid,$resourceGroupName,$poolName,$wvdapi)
                $hostsquery = ("/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.DesktopVirtualization/hostPools/{2}/SessionHosts?api-version={3}" -f $subscriptionid,$resourceGroupName,$poolName,$wvdapi)
                $vmquery = ("/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Compute/virtualMachines?api-version=2020-06-01" -f $subscriptionid,$resourceGroupName)

                $sessions = (Query-Azure $sessionsquery $token).Value
                $hosts = (Query-Azure $hostsquery $token).Value
                $vms = (Query-Azure $vmquery $token).Value

                Write-Output ("Creating Azure Monitor Metric Definitions")
                [System.Collections.Generic.List[System.Object]]$metricDefinitions = @(
                    [pscustomobject]@{
                        NameSpace = "Virtual Desktop"
                        Metric = "Active Sessions"
                        Dimensions = "Workspace:$workspacename;Pool:$poolname"
                        Query = { ($sessions.properties | Where-Object {$_.sessionstate -eq "Active" -AND $_.userprincipalname -ne $null}).Count }
                    },
                    [pscustomobject]@{
                        NameSpace = "Virtual Desktop"
                        Metric = "Disconnected Sessions"
                        Dimensions = "Workspace:$workspacename;Pool:$poolname"
                        Query = { ($sessions.properties | Where-Object {$_.sessionState -eq "Disconnected" -AND $_.userPrincipalName -ne $null}).Count }
                    },
                    [pscustomobject]@{
                        NameSpace = "Virtual Desktop"
                        Metric = "Total Sessions"
                        Dimensions = "Workspace:$workspacename;Pool:$poolname"
                        Query = { ($sessions.properties | Where-Object {$_.userPrincipalName -ne $null}).Count }
                    },
                    [pscustomobject]@{
                        NameSpace = "Virtual Desktop"
                        Metric = "Draining Hosts"
                        Dimensions = "Workspace:$workspacename;Pool:$poolname"
                        Query = { ($hosts.properties | Where-Object {$_.allowNewSession -eq $false}).Count }
                    },
                    [pscustomobject]@{
                        NameSpace = "Virtual Desktop"
                        Metric = "Unhealthy Hosts"
                        Dimensions = "Workspace:$workspacename;Pool:$poolname"
                        Query = { ($hosts.properties | Where-Object {$_.allowNewSession -eq $true -AND $_.status -ne "Available"}).Count }
                    },
                    [pscustomobject]@{
                        NameSpace = "Virtual Desktop"
                        Metric = "Healthy Hosts"
                        Dimensions = "Workspace:$workspacename;Pool:$poolname"
                        Query = { ($hosts.properties | Where-Object {$_.allowNewSession -eq $true -AND $_.status -eq "Available"}).Count }
                    },
                    [pscustomobject]@{
                        NameSpace = "Virtual Desktop"
                        Metric = "Max Sessions in Pool"
                        Dimensions = "Workspace:$workspacename;Pool:$poolname"
                        Query = {
                            $healthyHosts = ($hosts.properties | Where-Object {$_.allowNewSession -eq $true -AND $_.status -eq "Available"}).Count
                            $healthyHosts * $hostpool.properties.maxSessionLimit
                        }
                    },
                    [pscustomobject]@{
                        NameSpace = "Virtual Desktop"
                        Metric = "Available Sessions in Pool"
                        Dimensions = "Workspace:$workspacename;Pool:$poolname"
                        Query = {
                            $healthyHosts = ($hosts.properties | Where-Object {$_.allowNewSession -eq $true -AND $_.status -eq "Available"}).Count
                            $totalSessions = ($hosts.properties | Where-Object {$_.allowNewSession -eq $true -AND $_.status -eq "Available"} | Measure-Object -Property Sessions -Sum).Sum
                            $maxSessions = $healthyHosts * $hostpool.properties.maxSessionLimit
                            $maxSessions - $totalSessions
                        }        
                    },
                    [pscustomobject]@{
                        NameSpace = "Virtual Desktop"
                        Metric = "Session Load (%)"
                        Dimensions = "Workspace:$workspacename;Pool:$poolname"
                        Query = {
                            $healthyHosts = ($hosts.properties | Where-Object {$_.allowNewSession -eq $true -AND $_.status -eq "Available"}).Count
                            $totalSessions = ($hosts.properties | Where-Object {$_.allowNewSession -eq $true -AND $_.status -eq "Available"} | Measure-Object -Property Sessions -Sum).Sum
                            $maxSessions = $healthyHosts * $hostpool.properties.maxSessionLimit
                            If ($maxSessions -eq 0) { $maxSessions }
                            Else { [math]::Ceiling($totalSessions / $maxSessions * 100) }
                        }
                    },
                    [pscustomobject]@{
                        NameSpace = "Virtual Desktop"
                        Metric = "Session Hosts in Maintenance"
                        Dimensions = "Workspace:$workspacename;Pool:$poolname"
                        Query = { ($vms.Tags | Where-Object {$_.'WVD-Maintenance' -eq $true}).Count }
                    }
                )

                Foreach ($metric in $metricDefinitions) {
                    Write-Output ("Publishing Metric: [{0}] - {1}" -f $metric.Namespace,$metric.Metric)
                    $metricPosted = Publish-Metric $metric $sessions $hosts $vms $poolName $azmontoken $workspaceId $workspaceRegion
                    If ($metricPosted -eq $false) { Write-Warning ("Failed to Publish Metric: [{0}] - {1}" -f $metric.Namespace,$metric.Metric) }
                }
            }
        }
        Else { Write-Warning ("No Host Pools found in {0} Resource Group" -f $resourceGroupName) }
    }
}
