[CmdletBinding()]
Param (
    $WvdRgName = "WVD-PROD-MAP-EASTUS-POOL-RG-5",
    $StgAcctRgName  ="WVD-CORE-MAP-EASTUS-SVCS-RG",
    $HostPoolName = "vac30-wvd-hostpool-05",
    $DeploymentType = "BYOD",
    $FSLogixVHDLocation = "\\vac30hsm01-6833.va.gov\vac30-wvd-netapp-pool01-vol02",
    $StgAcctSubscription = "WVD-Public-Core",
    $StgAcctName = "vac30artifactblobstore"
)

$WvdRgName = "WVD-PROD-MAP-EASTUS-POOL-RG-6"
$StgAcctRgName  ="WVD-CORE-MAP-EASTUS-SVCS-RG"
$HostPoolName = "vac30-wvd-hostpool-06"
$DeploymentType = "GFE"
$FSLogixVHDLocation = "\\vac30hsm01-6833.va.gov\vac30-wvd-netapp-pool01-vol02"
$StgAcctSubscription = "WVD-Public-Core"
$StgAcctName = "vac30artifactblobstore"

$expirationTime = (Get-Date).AddHours(24)
$wvdAzContext = Get-AzContext
$coreAzContext = Set-AzContext -Subscription $StgAcctSubscription
$wvdAzContext | Set-AzContext
$vmNames = Get-AzVm -ResourceGroupName $WvdRgName | ForEach-Object {$_.Name}
$stgAccountContext = (Get-AzStorageAccount -Name $StgAcctName -ResourceGroupName $StgAcctRgName -DefaultProfile $coreAzContext).Context
$dscZipUri = New-AzStorageBlobSASToken -Container dsc -Blob "WvdWin10Config.ps1.zip" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
$dscTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "WindowsVirtualDesktop/WvdWin10Config.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
$wvdHostPoolToken = New-AzWvdRegistrationInfo -ResourceGroupName $WvdRgName -HostPoolName $HostPoolName -ExpirationTime $expirationTime

$templateParams = @{
    az_virtualMachineNames = $vmNames
    wvd_deploymentType = $DeploymentType
    wvd_fsLogixVHDLocation = $FSLogixVHDLocation
    wvd_hostPoolName = $HostPoolName
    wvd_hostPoolToken = $wvdHostPoolToken.Token
    wvd_sessionHostDSCModuleZipUri = $dscZipUri
    wvd_sessionHostDSCTemplateUri = $dscTemplateUri
    ResourceGroupName = $WvdRgName
}

New-AzResourceGroupDeployment @templateParams -TemplateFile _SessionHostConfig.json -TemplateParameterFile _SessionHostConfig.parameters.json -Verbose