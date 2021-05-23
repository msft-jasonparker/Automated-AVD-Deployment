Function Expand-AzWvdHostPool {
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Parameter(Mandatory=$true)]
        [System.String]$SubscriptionName,

        [Parameter(Mandatory=$true)]
        [System.String]$ResourceGroupName,

        [Parameter(Mandatory=$true)]
        [System.String]$HostPoolName,

        [Parameter(Mandatory=$true)]
        [Int]$NumberOfInstances,

        [Parameter(Mandatory=$false)]
        [System.String]$StorageAccountResourceGroup = "WVD-CORE-MAP-EASTUS-SVCS-RG",

        [Parameter(Mandatory=$false)]
        [System.String]$StorageAccountSubscription = "WVD-Public-Core",

        [Parameter(Mandatory=$false)]
        [System.String]$StorageAccountName = "vac30artifactblobstore"
    )
    PROCESS {
        Write-Host ("[{0}] Setting up inital variables..." -f (Get-Date))
        $expirationTime = (Get-Date).AddHours(24)

        Write-Host ("[{0}] Connecting to Azure Cloud..." -f (Get-Date))
        Set-AzContext -Subscription $StorageAccountSubscription | Out-Null
        
        $coreContext = Get-AzContext
        Write-Host ("`tConnected to: {0}, using {1}" -f $coreContext.Name.Split("(")[0].Trim(" "),$coreContext.Account.Id)

        Write-Host ("[{0}] Generating Storage SAS Tokens and fetching various URL(s)..." -f (Get-Date))  
        
        If (Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroup) {
            $stgAccountContext = (Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroup -DefaultProfile $coreContext).Context
        }
        Else { Throw "Unable to locate Storage Account" }
        
        $wvdSessionHostTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "WindowsVirtualDesktop/Deploy-WVD-SessionHosts.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $wvdHostPoolExpansionTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "WindowsVirtualDesktop/Expand-WVD-HostPool.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $wvdHostPoolExpansionParamUri = New-AzStorageBlobSASToken -Container templates -Blob "WindowsVirtualDesktop/Expand-WVD-HostPool.parameters.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        (New-Object System.Net.WebClient).DownloadFile($wvdHostPoolExpansionParamUri,("{0}\wvd.parameters.json" -f $env:TEMP))
        
        $DscTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob ("WindowsVirtualDesktop/Deploy-WVD-BaselineConfig.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $DscTemplateParamUri = New-AzStorageBlobSASToken -Container templates -Blob ("WindowsVirtualDesktop/Deploy-WVD-BaselineConfig.parameters.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        (New-Object System.Net.WebClient).DownloadFile($DscTemplateParamUri,("{0}\dsc.parameters.json" -f $env:TEMP))

        $wvdContext = Set-AzContext -Subscription $subscriptionName
        Write-Host ("`tConnected to: {0}, using {1}" -f $wvdContext.Name.Split("(")[0].Trim(" "),$wvdContext.Account.Id)

        $HostPool = Get-AzWvdHostPool -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName
        
        $StartingIncrement = (Get-AzVm -ResourceGroupName $ResourceGroupName | ForEach-Object { # Interate through each VM in the Resource Group
            $vmName = $_.Name # Store the VM Name
            [Double]$vmName.Substring($vmName.Length - 3) # Create a [Double] using the last 3 characters of the VM name
        } | Sort-Object -Descending | Select-Object -First 1) + 1 # After the interation, sort the number in decending order, select the first 1, then add 1 to it
        
        $Properties = $hostPool.Description.replace("\","\\") | ConvertFrom-Json
        $vmTemplate = $HostPool.VMTemplate | ConvertFrom-Json
        

        Write-Host ("[{0}] Starting WVD Host Pool Expansion..." -f (Get-Date))
        $deploymentString = ([Guid]::NewGuid()).Guid.Split("-")[-1]
        $Results = New-AzResourceGroupDeployment `
            -Name ("Expand-WVD-HostPool-{0}" -f $deploymentString) `
            -ResourceGroupName $ResourceGroupName `
            -TemplateUri $wvdHostPoolExpansionTemplateUri `
            -TemplateParameterFile ("{0}\wvd.parameters.json" -f $env:TEMP) `
            -vn_subnetName ("N2-Subnet-{0}" -f $HostPoolName.Split("-")[-1]) `
            -az_deploymentString $deploymentString `
            -az_vmSize $vmTemplate.vmSize.Id `
            -az_vmNumberOfInstances $NumberOfInstances `
            -az_vmStartingIncrement $StartingIncrement `
            -az_vmImageOffer $vmTemplate.galleryImageOffer `
            -az_vmImagePublisher $vmTemplate.galleryImagePublisher `
            -az_vmImageSKU $vmTemplate.galleryImageSku `
            -az_vmDiskType $vmTemplate.osDiskType `
            -wvd_shPrefix $vmTemplate.namePrefix `
            -wvd_hostpoolName $HostPoolName `
            -wvd_buildVersion $HostPool.Tag["WVD-Build"] `
            -wvd_sessionHostTemplateUri $wvdSessionHostTemplateUri `
            -domain $vmTemplate.domain

        If ($Results.ProvisioningState -eq "Succeeded") {
            Write-Host ("[{0}] WVD Host Pool Expansion Succeeded!" -f $Results.Timestamp.ToLocalTime())

            $wvdDscConfigZipUrl = Get-LatestWVDConfigZip -OutputType Local -LocalPath $HostPool.Tag["WVD-ArtifactLocation"] -Verbose:$false

            $dscZipUri = New-AzStorageBlobSASToken -Container dsc -Blob ("{0}" -f $HostPool.Tag["WVD-DscConfiguration"]) -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri

            Write-Host ("[{0}] Host Pool: {1} | Generating Host Pool registration token..." -f (Get-Date), $HostPoolName)
            $wvdHostPoolToken = (Update-AzWvdHostPool -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -RegistrationInfoExpirationTime $expirationTime -RegistrationInfoRegistrationTokenOperation Update).RegistrationInfoToken
            #$wvdHostPoolToken = New-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -ExpirationTime $expirationTime
            $vmNames = Get-AzVM -ResourceGroupName $ResourceGroupName -Status | ForEach-Object {$_.Name}

            Write-Host ("[{0}] Host Pool: {1} | Starting WVD Session Host Configuration..." -f (Get-Date), $HostPoolName)
            $templateParams = [Ordered]@{
                Name = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                az_virtualMachineNames = $vmNames
                az_vmImagePublisher = $Properties.imagePublisher
                wvd_dscConfigurationScript = $HostPool.Tag["WVD-DscConfiguration"].Trim(".zip")
                wvd_dscConfigZipUrl = $wvdDscConfigZipUrl
                wvd_deploymentType = $HostPool.Tag["WVD-Deployment"]
                wvd_deploymentFunction = $HostPool.Tag["WVD-Function"]
                wvd_fsLogixVHDLocation = $HostPool.Tag["WVD-FsLogixVhdLocation"]
                wvd_hostPoolName = $HostPoolName
                wvd_hostPoolToken = $wvdHostPoolToken
                wvd_sessionHostDSCModuleZipUri = $dscZipUri
                ResourceGroupName = $ResourceGroupName
                TemplateUri = $DscTemplateUri
                TemplateParameterFile = ("{0}\dsc.parameters.json" -f $env:TEMP)
            }
            
            New-AzResourceGroupDeployment @templateParams -AsJob | Out-Null

            _WaitOnJobs
            
            Get-Job | Group-Object State -NoElement
            #>
        }
        Else { Write-Host ("[{0}] WVD Session Host Deployment did not succeed - State: {1}" -f (Get-Date),$Results.ProvisioningState)}
    }
}