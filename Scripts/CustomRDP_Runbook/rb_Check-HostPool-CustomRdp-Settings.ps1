[CmdletBinding()]
Param (
    [Parameter(Mandatory=$true)]
    [System.String]$SubscriptionId
)

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
Write-Output ("Connecting to Azure Subscription ({0})" -f $SubscriptionId)
$azContext = Set-AzContext -Subscription $SubscriptionId
If ($azContext) {Write-Output ("[{0}] Connected to the subscription" -f ($azContext.Name -split " ")[0])}
Else {
    Write-Output ("[{0}] - Azure Context not found!" -f $SubscriptionId)
    Write-Error -Exception "Invalid Azure Context" -Message ("Unable to create an Azure Context under the {0} subscription" -f ($azContext.Name -split " ")[0]) -Category "OperationStopped" -ErrorAction Stop
}
#endregion

$CustomRdpProperties = "audiomode:i:0;audiocapturemode:i:1;encode redirected video capture:i:1;redirected video capture encoding quality:i:1;camerastoredirect:s:*;drivestoredirect:s:;redirectclipboard:i:0;redirectprinters:i:0;use multimon:i:0;singlemoninwindowedmode:i:1;maximizetocurrentdisplays:i:1;screen mode id:i:2;smart sizing:i:0;dynamic resolution:i:1;authentication level:i:0;gatewaycredentialssource:i:0;Kdcproxyname:s:kproxy.federation.va.gov"
$KdcProxySetting = "Kdcproxyname:s:kproxy.federation.va.gov"

Write-Output ("Validating Host Pool CustomRDPProperty Settings")
$hostPools = Get-AzWvdHostPool
Foreach ($hostPool in $hostPools) {
    $resourceGroupName = $hostpool.id.Split("/")[4]
    If ($hostPool.CustomRdpProperty.contains($KdcProxySetting)) {
        Write-Output ("[{0}] Host Pool has the correct RDP settings for KDC Proxy" -f $hostPool.Name)
    }
    Else {
        Write-Output ("[{0}] Host Pool is missing the KDC Proxy settings" -f $hostPool.Name)
        $update = Update-AzWvdHostPool -Name $hostPool.Name -ResourceGroupName $resourceGroupName -CustomRdpProperty $CustomRdpProperties
        If ($update) {Write-Output ("[{0}] Host Pool updated with the correct Custom RDP Properties" -f $hostPool.Name)}
        Else {Write-Warning ("[{0}] Host Pool was not updated")}
    }
}