Function New-AzWvdSessionHosts {
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
    Param (
        [Parameter(Mandatory=$true)]
        [ArgumentCompleter({
            Param($CommandName,$ParameterName,$WordsToComplete,$CommandAst,$FakeBoundParameters)
            Get-AzSubscription | Where-Object {$_.Name -like "$WordsToComplete*"} | Select-Object -ExpandProperty Name
        })]
        [System.String]$SubscriptionName,

        [Parameter(Mandatory=$true)]
        [ArgumentCompleter({
            Param($CommandName,$ParameterName,$WordsToComplete,$CommandAst,$FakeBoundParameters)
            Get-AzSubscription | Where-Object {$_.Name -like "$WordsToComplete*"} | Select-Object -ExpandProperty Name
        })]
        [System.String]$StorageAccountSubscription,

        # Name of the Resource Group of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$ResourceGroupName,

        # Name of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.DesktopVirtualization/hostpools","ResourceGroupName")]
        [System.String]$HostPoolName,

        # Group of Session Hosts to target (A or B)
        [Parameter(Mandatory=$true)]
        [ValidateSet("A","B","ALL")]
        [String]$SessionHostGroup,

        [Parameter(Mandatory=$true)]
        [Int]$NumberOfInstances,

        # Name of the Resource Group of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$StorageAccountResourceGroup,

        # Name of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Storage/storageAccounts","StorageAccountResourceGroup")]
        [System.String]$StorageAccountName,

        # Name of the Resource Group of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$VirtualNetworkResourceGroup,

        # Name of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Network/virtualNetworks","VirtualNetworkResourceGroup")]
        [System.String]$VirtualNetworkName,

        # Name of the Resource Group of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$LogAnalyticsResourceGroup,

        # Name of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.OperationalInsights/workspaces","LogAnalyticsResourceGroup")]
        [System.String]$LogAnalyticsWorkspace
    )
    BEGIN {
        $azContext = Get-AzContext
        
        If ($azContext) {
            Write-Host ("[{0}] Connecting to Azure Cloud..." -f (Get-Date))
            $coreContext = Set-AzContext -Subscription $StorageAccountSubscription
            Write-Host ("`tConnected to: {0}, using {1}" -f $coreContext.Name.Split(" ")[0],$coreContext.Account.Id)
        }
        Else {
            $coreContext = Connect-AzAccount -Subscription $StorageAccountSubscription
            Write-Host ("`tConnected to: {0}, using {1}" -f $coreContext.Context.Subscription.Name,$coreContext.Context.Account.Id)
        }

        $userName = ("{0} ({1})" -f $azContext.Account.Id,$azContext.Account.Type)
    }
    PROCESS {
        Write-Host ("[{0}] Setting up inital variables..." -f (Get-Date))
        $expirationTime = (Get-Date).AddHours(24)        

        Write-Host ("[{0}] Generating Storage SAS Tokens and fetching various URL(s)..." -f (Get-Date))
        $stgAccountContext = (Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroup -DefaultProfile $coreContext).Context
        
        $wvdSessionHostTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "WindowsVirtualDesktop/Deploy-WVD-SessionHosts.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $wvdSessionHostTemplateParamUri = New-AzStorageBlobSASToken -Container templates -Blob "WindowsVirtualDesktop/Deploy-WVD-SessionHosts.parameters.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        (New-Object System.Net.WebClient).DownloadFile($wvdSessionHostTemplateParamUri,("{0}\wvd.parameters.json" -f $env:TEMP))
        
        $DscTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob ("WindowsVirtualDesktop/Deploy-WVD-BaselineConfig.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $DscTemplateParamUri = New-AzStorageBlobSASToken -Container templates -Blob ("WindowsVirtualDesktop/Deploy-WVD-BaselineConfig.parameters.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        (New-Object System.Net.WebClient).DownloadFile($DscTemplateParamUri,("{0}\dsc.parameters.json" -f $env:TEMP))

        $wvdContext = Set-AzContext -Subscription $subscriptionName
        Write-Host ("`tConnected to: {0}, using {1}" -f $wvdContext.Name.Split("(")[0].Trim(" "),$wvdContext.Account.Id)
        $azLogAnalyticsId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspace -WarningAction SilentlyContinue).CustomerId.ToString()
        $azLogAnalyticsKey = (Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspace -WarningAction SilentlyContinue).PrimarySharedKey

        $HostPool = Get-AzWvdHostPool -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName
        $vmTemplate = $HostPool.VMTemplate | ConvertFrom-Json
        $hostPoolProperties = $HostPool.Description.Replace("\","\\") | ConvertFrom-Json
        $subnetId = Get-AzVirtualNetwork -Name $VirtualNetworkName -ResourceGroupName $VirtualNetworkResourceGroup | Get-AzVirtualNetworkSubnetConfig -Name ("N2-Subnet-{0}" -f $HostPoolName.Split("-")[-1]) | Select-Object -ExpandProperty Id

        Write-Host ("[{0}] Starting WVD Session Host Deployment..." -f (Get-Date))
        $correlationId = [Guid]::NewGuid()
        $deploymentString = $correlationId.Guid.Split("-")[-1]

        If ($SessionHostGroup -eq "ALL") {
            $Groups = "A","B"
            [System.Collections.Generic.List[System.Object]]$Global:deploymentJobs = @()
            Foreach ($Group in $Groups) {
                Write-Host ("[{0}] Session Host Group: {1} | Starting WVD Session Host Deployment..." -f (Get-Date), $Group)

                $logEntry = [PSCustomObject]@{
                    Timestamp = [DateTime]::UtcNow.ToString('o')
                    CorrelationId = $correlationId
                    Computer = $env:COMPUTERNAME
                    UserName = $userName
                    EntryType = "INFO"
                    Subscription = $subscriptionName
                    ResourceGroupName = $ResourceGroupName
                    DeploymentName = ("Deploy-WVD-SessionHosts-Group-{0}-{1}" -f $Group,$deploymentString)
                    DeploymentStatus = "Starting"
                    DeploymentType = "Deployment"
                    HostPoolName = $HostPoolName
                }
                New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false

                $templateParams = [Ordered]@{
                    Name = ("Deploy-WVD-SessionHosts-Group-{0}-{1}" -f $Group,$deploymentString)
                    ResourceGroupName = $ResourceGroupName
                    TemplateUri = $wvdSessionHostTemplateUri
                    TemplateParameterFile = ("{0}\wvd.parameters.json" -f $env:TEMP)
                    az_vmSize = $vmTemplate.vmSize.Id
                    az_vmNumberOfInstances = [math]::Ceiling($NumberOfInstances/$Groups.Count)
                    az_vmStartingIncrement = 1
                    az_vmNamePrefix = $vmTemplate.namePrefix
                    az_vmImageOffer = $vmTemplate.galleryImageOffer
                    az_vmImagePublisher = $vmTemplate.galleryImagePublisher
                    az_vmImageSKU = $vmTemplate.galleryImageSku
                    az_vmDiskType = $vmTemplate.osDiskType
                    wvd_groupReference = $Group
                    wvd_buildVersion = $HostPool.Tag["WVD-Build"]
                    wvd_subnetId = $subnetId
                    wvd_hostpoolName = $HostPoolName
                }
                
                Write-Debug ("Start Session Host Group Deployment: {0}" -f $Group)
                New-AzResourceGroupDeployment @templateParams -AsJob | Out-Null
                While ($true) {
                    $jobInfo = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name ("Deploy-WVD-SessionHosts-Group-{0}-{1}" -f $Group,$deploymentString) -ErrorAction SilentlyContinue
                    If ($jobInfo) {
                        $logEntry = [PSCustomObject]@{
                            Timestamp = [DateTime]::UtcNow.ToString('o')
                            CorrelationId = $correlationId
                            Computer = $env:COMPUTERNAME
                            UserName = $userName
                            EntryType = "INFO"
                            Subscription = $subscriptionName
                            ResourceGroupName = $ResourceGroupName
                            DeploymentName = ("Deploy-WVD-SessionHosts-Group-{0}-{1}" -f $Group,$deploymentString)
                            DeploymentStatus = $jobInfo.ProvisioningState
                            DeploymentType = "Deployment"
                            HostPoolName = $HostPoolName
                        }
                        New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                        [Void]$deploymentJobs.Add($jobInfo)
                        Break
                    }
                    Else {
                        Write-Verbose ("[{0}] Waiting for job: Deploy-WVD-SessionHosts-Group-{1}-{2}" -f (Get-Date),$Group,$deploymentString)
                        Start-Sleep -Seconds 5
                    }
                }
            }

            $currentTime = [DateTime]::UtcNow
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            Do {
                $i = 0
                [System.Collections.Generic.List[System.Object]]$Jobs = @()
                Foreach ($Job in $deploymentJobs) {
                    $deploymentResults = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name $Job.DeploymentName -ErrorAction SilentlyContinue
                    If ($deploymentResults) {
                        If ($deploymentResults.ProvisioningState -eq "Running") {$i++}
                        $elapsedTime = $deploymentResults.TimeStamp.ToUniversalTime() - $currentTime.ToUniversalTime()
                        $obj = [PSCustomObject][Ordered]@{
                            Name = $deploymentResults.DeploymentName
                            ResourceGroup = ("{0}  " -f $deploymentResults.ResourceGroupName)
                            Status = ("{0}  " -f $deploymentResults.ProvisioningState)
                            Duration = ("{0:N0}.{1:N0}:{2:N0}:{3:N0}" -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds)
                        }
                        $Jobs.Add($obj)
                    }
                    Else {
                        $i++
                        $obj = [PSCustomObject][Ordered]@{
                            Name = $deploymentResults.DeploymentName
                            ResourceGroup = ("{0}  " -f $deploymentResults.ResourceGroupName)
                            Status = ("Not Found  ")
                            Duration = ("N/A")
                        }
                        $Jobs.Add($obj)
                    }
                }

                If ($SelfHosted) { Write-Host "." -NoNewline }
                Else {
                    Show-Menu -Title ("Job Status") -DisplayOnly -Style Info -Color Cyan -ClearScreen
                    $Jobs | Sort-Object 'ResourceGroup' -Descending | Format-Table -AutoSize | Out-Host
                    
                    Write-Host "`n`rNext refresh in " -NoNewline
                    Write-Host "15" -ForegroundColor Magenta -NoNewline
                    Write-Host " Seconds`r`n"
                }
                If ($stopWatch.Elapsed.TotalMinutes -gt 89) {
                    Write-Warning ("One or More of the Deployment Jobs has exceeded 90 minutes deployment time!")
                    Break
                }
                Start-Sleep -Seconds 15

            } Until ($i -eq 0)
            Write-Host "Done!`n`r"

            Foreach ($Job in $deploymentJobs) {
                $jobInfo = Get-AzResourceGroupDeployment -ResourceGroupName $Job.ResourceGroupName -Name $Job.DeploymentName -ErrorAction SilentlyContinue
                
                If ($jobInfo.ProvisioningState -eq "Succeeded") {
                    $type = "INFO"
                    $jobsSucceeded++
                }
                ElseIf ($jobInfo.ProvisioningState -eq "Cancelled") { $type = "WARNING" }
                Else { $type = "ERROR" }

                $logEntry = [PSCustomObject]@{
                    Timestamp = [DateTime]::UtcNow.ToString('o')
                    CorrelationId = $correlationId
                    Computer = $env:COMPUTERNAME
                    UserName = $userName
                    EntryType = $type
                    Subscription = $subscriptionName
                    ResourceGroupName = $jobInfo.ResourceGroupName
                    DeploymentName = $jobInfo.DeploymentName
                    DeploymentStatus = $jobInfo.ProvisioningState
                    DeploymentType = "Deployment"
                    HostPoolName = $HostPoolName
                }
                New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
            }

            If ($jobsSucceeded -lt $Groups.Count) { 
                Write-Warning ("One or More Deployments did not succeed, DSC Configuration will be skipped!")
                Return
            }

            $vmNames = Get-AzVM -ResourceGroupName $ResourceGroupName | ForEach-Object { $_.Name }
            $wvdDscConfigZipUrl = Get-LatestWVDConfigZip -OutputType Local -LocalPath $HostPool.Tag["WVD-ArtifactLocation"] -Verbose:$false
            $dscZipUri = New-AzStorageBlobSASToken -Container dsc -Blob $hostPool.Tag["WVD-DscConfiguration"] -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri

            Write-Host ("[{0}] Host Pool: {1} | Generating Host Pool registration token..." -f (Get-Date), $HostPoolName)
            $wvdHostPoolToken = (Update-AzWvdHostPool -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -RegistrationInfoExpirationTime $expirationTime -RegistrationInfoRegistrationTokenOperation Update).RegistrationInfoToken
            
            Write-Host ("[{0}] Host Pool: {1} | Starting WVD Session Host Configuration..." -f (Get-Date), $HostPoolName)
            $logEntry = [PSCustomObject]@{
                Timestamp = [DateTime]::UtcNow.ToString('o')
                CorrelationId = $correlationId
                Computer = $env:COMPUTERNAME
                UserName = $userName
                EntryType = "INFO"
                Subscription = $subscriptionName
                ResourceGroupName = $ResourceGroupName
                DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                DeploymentStatus = "Starting"
                HostPoolName = $HostPoolName
            }
            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false

            $templateParams = [Ordered]@{
                Name = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                az_virtualMachineNames = $vmNames
                az_vmImagePublisher = $vmTemplate.galleryImagePublisher
                wvd_dscConfigurationScript = $hostPool.Tag["WVD-DscConfiguration"].Trim(".zip")
                wvd_dscConfigZipUrl = $wvdDscConfigZipUrl
                wvd_deploymentType = $HostPool.Tag["WVD-Deployment"]
                wvd_deploymentFunction = $HostPool.Tag["WVD-Function"]
                wvd_fsLogixVHDLocation = $HostPool.Tag["WVD-FsLogixVhdLocation"]
                wvd_ArtifactLocation = $HostPool.Tag["WVD-ArtifactLocation"]
                wvd_hostPoolName = $HostPoolName
                wvd_hostPoolToken = $wvdHostPoolToken
                wvd_sessionHostDSCModuleZipUri = $dscZipUri
                ResourceGroupName = $ResourceGroupName
                TemplateUri = $DscTemplateUri
                TemplateParameterFile = ("{0}\dsc.parameters.json" -f $env:TEMP)
            }
            
            $deploymentJob = New-AzResourceGroupDeployment @templateParams -AsJob
            If ($deploymentJob) {
                try {
                    While ($true) {
                        If (Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue) { Break }
                        Else {
                            Write-Verbose ("[{0}] Waiting for job: Deploy-WVD-DscConfiguration-{1}" -f (Get-Date),$deploymentString)
                            Start-Sleep -Seconds 5
                        }
                    }

                    $deploymentInfo = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                    $logEntry = [PSCustomObject]@{
                        Timestamp = [DateTime]::UtcNow.ToString('o')
                        CorrelationId = $correlationId
                        Computer = $env:COMPUTERNAME
                        UserName = $userName
                        EntryType = "INFO"
                        Subscription = $subscriptionName
                        ResourceGroupName = $ResourceGroupName
                        DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                        DeploymentStatus = $deploymentInfo.ProvisioningState
                        HostPoolName = $HostPoolName
                    }
                    New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                }
                catch {
                    Write-Warning ("WVD DSC Configuration Deployment encountered a problem")
                    $logEntry = [PSCustomObject]@{
                        Timestamp = [DateTime]::UtcNow.ToString('o')
                        CorrelationId = $correlationId
                        Computer = $env:COMPUTERNAME
                        UserName = $userName
                        EntryType = "ERROR"
                        Subscription = $subscriptionName
                        ResourceGroupName = $ResourceGroupName
                        DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                        DeploymentStatus = $_.Exception.Message
                        HostPoolName = $HostPoolName
                    }
                    New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                    Return
                }
            }
            Else {
                Write-Warning ("WVD DSC Configuration Deployment failed to start")
                $logEntry = [PSCustomObject]@{
                    Timestamp = [DateTime]::UtcNow.ToString('o')
                    CorrelationId = $correlationId
                    Computer = $env:COMPUTERNAME
                    UserName = $userName
                    EntryType = "ERROR"
                    Subscription = $subscriptionName
                    ResourceGroupName = $ResourceGroupName
                    DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                    DeploymentStatus = "NotStarted"
                    HostPoolName = $HostPoolName
                }
                New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                Return
            }
            
            $currentTime = [DateTime]::UtcNow
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            Do {
                $i = 0
                $deploymentResults = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue
                If ($deploymentResults) {
                    If ($deploymentResults.ProvisioningState -eq "Running") {$i++}
                    $elapsedTime = $deploymentResults.TimeStamp.ToUniversalTime() - $currentTime.ToUniversalTime()
                    $objJob = [PSCustomObject][Ordered]@{
                        Name = $deploymentResults.DeploymentName
                        ResourceGroup = ("{0}  " -f $ResourceGroupName)
                        Status = ("{0}  " -f $deploymentResults.ProvisioningState)
                        Duration = ("{0:N0}.{1:N0}:{2:N0}:{3:N0}" -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds)
                    }
                }
                Else {
                    $i++
                    Write-Warning ("Failed to get Deployment Results for: {0} in {1}" -f ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString),$outputHash[$hostPool].resourceGroupName)
                    $logEntry = [PSCustomObject]@{
                        Timestamp = [DateTime]::UtcNow.ToString('o')
                        CorrelationId = $correlationId
                        Computer = $env:COMPUTERNAME
                        UserName = $userName
                        EntryType = "WARNING"
                        Subscription = $subscriptionName
                        ResourceGroupName = $ResourceGroupName
                        DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                        DeploymentStatus = "Unknown"
                        HostPoolName = $HostPoolName
                    }
                    New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                }

                If ($SelfHosted) { Write-Host "." -NoNewline }
                Else {
                    Show-Menu -Title ("Job Status") -DisplayOnly -Style Info -Color Cyan -ClearScreen
                    $objJob | Format-Table -AutoSize
                    
                    Write-Host "`n`rNext refresh in " -NoNewline
                    Write-Host "15" -ForegroundColor Magenta -NoNewline
                    Write-Host " Seconds`r`n"
                }
                If ($stopWatch.Elapsed.TotalMinutes -gt 89) {
                    Write-Warning ("One or More of the Deployment Jobs has exceeded a 90 minutes deployment time!")
                    Break
                }
                Start-Sleep -Seconds 15

            } Until ($i -eq 0)
            Write-Host "Done!`n`r"

            $job = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue
                
            If ($job.ProvisioningState -eq "Succeeded") { $type = "INFO" }
            ElseIf ($job.ProvisioningState -eq "Cancelled") { $type = "WARNING" }
            Else { $type = "ERROR" }

            $logEntry = [PSCustomObject]@{
                Timestamp = [DateTime]::UtcNow.ToString('o')
                CorrelationId = $correlationId
                Computer = $env:COMPUTERNAME
                UserName = $userName
                EntryType = $type
                Subscription = $subscriptionName
                ResourceGroupName = $ResourceGroupName
                DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                DeploymentStatus = $job.ProvisioningState
                HostPoolName = $HostPoolName
            }
            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
            Disable-AzWvdMaintanence -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -SessionHostGroup $SessionHostGroup -LogAnalyticsResourceGroup $LogAnalyticsResourceGroup -LogAnalyticsWorkspace $LogAnalyticsWorkspace -CorrelationId $correlationId
        }
        Else {

            $logEntry = [PSCustomObject]@{
                Timestamp = [DateTime]::UtcNow.ToString('o')
                CorrelationId = $correlationId
                Computer = $env:COMPUTERNAME
                UserName = $userName
                EntryType = "INFO"
                Subscription = $subscriptionName
                ResourceGroupName = $ResourceGroupName
                DeploymentName = ("Deploy-WVD-SessionHosts-Group-{0}-{1}" -f $SessionHostGroup,$deploymentString)
                DeploymentStatus = "Starting"
                HostPoolName = $HostPoolName
            }
            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false

            $Results = New-AzResourceGroupDeployment `
                -Name ("Deploy-WVD-SessionHosts-Group-{0}-{1}" -f $SessionHostGroup,$deploymentString) `
                -ResourceGroupName $ResourceGroupName `
                -TemplateUri $wvdSessionHostTemplateUri `
                -TemplateParameterFile ("{0}\wvd.parameters.json" -f $env:TEMP) `
                -az_vmSize $vmTemplate.vmSize.Id `
                -az_vmNumberOfInstances $NumberOfInstances `
                -az_vmStartingIncrement 1 `
                -az_vmNamePrefix $vmTemplate.namePrefix `
                -az_vmImageOffer $vmTemplate.galleryImageOffer `
                -az_vmImagePublisher $vmTemplate.galleryImagePublisher `
                -az_vmImageSKU $vmTemplate.galleryImageSku `
                -az_vmDiskType $vmTemplate.osDiskType `
                -wvd_groupReference $SessionHostGroup `
                -wvd_buildVersion $HostPool.Tag["WVD-Build"] `
                -wvd_subnetId $subnetId `
                -wvd_hostpoolName $HostPoolName `

            If ($Results.ProvisioningState -eq "Succeeded") {
                Write-Host ("[{0}] WVD Session Host Deployment Succeeded!" -f $Results.Timestamp.ToLocalTime())
                $logEntry = [PSCustomObject]@{
                    Timestamp = [DateTime]::UtcNow.ToString('o')
                    CorrelationId = $correlationId
                    Computer = $env:COMPUTERNAME
                    UserName = $userName
                    EntryType = "INFO"
                    Subscription = $subscriptionName
                    ResourceGroupName = $ResourceGroupName
                    DeploymentName = ("Deploy-WVD-SessionHosts-Group-{0}-{1}" -f $SessionHostGroup,$deploymentString)
                    DeploymentStatus = $Results.ProvisioningState
                    HostPoolName = $HostPoolName
                }
                New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                $vmNames = Get-AzVM -ResourceGroupName $ResourceGroupName -Status | Where-Object { $_.Tags["WVD-Group"] -eq $SessionHostGroup } | ForEach-Object { $_.Name }
                $wvdDscConfigZipUrl = Get-LatestWVDConfigZip -OutputType Local -LocalPath $HostPool.Tag["WVD-ArtifactLocation"] -Verbose:$false
                $dscZipUri = New-AzStorageBlobSASToken -Container dsc -Blob $hostPool.Tag["WVD-DscConfiguration"] -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri

                Write-Host ("[{0}] Host Pool: {1} | Generating Host Pool registration token..." -f (Get-Date), $HostPoolName)
                $wvdHostPoolToken = (Update-AzWvdHostPool -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -RegistrationInfoExpirationTime $expirationTime -RegistrationInfoRegistrationTokenOperation Update).RegistrationInfoToken
                #$wvdHostPoolToken = New-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -ExpirationTime $expirationTime
                
                Write-Host ("[{0}] Host Pool: {1} | Starting WVD Session Host Configuration..." -f (Get-Date), $HostPoolName)
                $logEntry = [PSCustomObject]@{
                    Timestamp = [DateTime]::UtcNow.ToString('o')
                    CorrelationId = $correlationId
                    Computer = $env:COMPUTERNAME
                    UserName = $userName
                    EntryType = "INFO"
                    Subscription = $subscriptionName
                    ResourceGroupName = $ResourceGroupName
                    DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                    DeploymentStatus = "Starting"
                    HostPoolName = $HostPoolName
                }
                New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false

                $templateParams = [Ordered]@{
                    Name = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                    az_virtualMachineNames = $vmNames
                    az_vmImagePublisher = $vmTemplate.galleryImagePublisher
                    wvd_dscConfigurationScript = $hostPool.Tag["WVD-DscConfiguration"].Trim(".zip")
                    wvd_dscConfigZipUrl = $wvdDscConfigZipUrl
                    wvd_deploymentType = $HostPool.Tag["WVD-Deployment"]
                    wvd_deploymentFunction = $HostPool.Tag["WVD-Function"]
                    wvd_fsLogixVHDLocation = $HostPool.Tag["WVD-FsLogixVhdLocation"]
                    wvd_ArtifactLocation = $HostPool.Tag["WVD-ArtifactLocation"]
                    wvd_hostPoolName = $HostPoolName
                    wvd_hostPoolToken = $wvdHostPoolToken
                    wvd_sessionHostDSCModuleZipUri = $dscZipUri
                    ResourceGroupName = $ResourceGroupName
                    TemplateUri = $DscTemplateUri
                    TemplateParameterFile = ("{0}\dsc.parameters.json" -f $env:TEMP)
                }
                
                $deploymentJob = New-AzResourceGroupDeployment @templateParams -AsJob
                If ($deploymentJob) {
                    try {
                        While ($true) {
                            If (Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue) { Break }
                            Else {
                                Write-Verbose ("[{0}] Waiting for job: Deploy-WVD-DscConfiguration-{1}" -f (Get-Date),$deploymentString)
                                Start-Sleep -Seconds 5
                            }
                        }

                        $deploymentInfo = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                        $logEntry = [PSCustomObject]@{
                            Timestamp = [DateTime]::UtcNow.ToString('o')
                            CorrelationId = $correlationId
                            Computer = $env:COMPUTERNAME
                            UserName = $userName
                            EntryType = "INFO"
                            Subscription = $subscriptionName
                            ResourceGroupName = $ResourceGroupName
                            DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                            DeploymentStatus = $deploymentInfo.ProvisioningState
                            HostPoolName = $HostPoolName
                        }
                        New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                    }
                    catch {
                        Write-Warning ("WVD DSC Configuration Deployment encountered a problem")
                        $logEntry = [PSCustomObject]@{
                            Timestamp = [DateTime]::UtcNow.ToString('o')
                            CorrelationId = $correlationId
                            Computer = $env:COMPUTERNAME
                            UserName = $userName
                            EntryType = "ERROR"
                            Subscription = $subscriptionName
                            ResourceGroupName = $ResourceGroupName
                            DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                            DeploymentStatus = $_.Exception.Message
                            HostPoolName = $HostPoolName
                        }
                        New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                        Return
                    }
                }
                Else {
                    Write-Warning ("WVD DSC Configuration Deployment failed to start")
                    $logEntry = [PSCustomObject]@{
                        Timestamp = [DateTime]::UtcNow.ToString('o')
                        CorrelationId = $correlationId
                        Computer = $env:COMPUTERNAME
                        UserName = $userName
                        EntryType = "ERROR"
                        Subscription = $subscriptionName
                        ResourceGroupName = $ResourceGroupName
                        DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                        DeploymentStatus = "NotStarted"
                        HostPoolName = $HostPoolName
                    }
                    New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                    Return
                }
                
                $currentTime = [DateTime]::UtcNow
                $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
                Do {
                    $i = 0
                    $deploymentResults = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue
                    If ($deploymentResults) {
                        If ($deploymentResults.ProvisioningState -eq "Running") {$i++}
                        $elapsedTime = $deploymentResults.TimeStamp.ToUniversalTime() - $currentTime.ToUniversalTime()
                        $objJob = [PSCustomObject][Ordered]@{
                            Name = ("Deploy-WVD-DscConfiguration-{0}  " -f $deploymentString)
                            ResourceGroup = ("{0}  " -f $ResourceGroupName)
                            Status = ("{0}  " -f $deploymentResults.ProvisioningState)
                            Duration = ("{0:N0}.{1:N0}:{2:N0}:{3:N0}" -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds)
                        }
                    }
                    Else {
                        $i++
                        Write-Warning ("Failed to get Deployment Results for: {0} in {1}" -f ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString),$outputHash[$hostPool].resourceGroupName)
                        $logEntry = [PSCustomObject]@{
                            Timestamp = [DateTime]::UtcNow.ToString('o')
                            CorrelationId = $correlationId
                            Computer = $env:COMPUTERNAME
                            UserName = $userName
                            EntryType = "WARNING"
                            Subscription = $subscriptionName
                            ResourceGroupName = $ResourceGroupName
                            DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                            DeploymentStatus = "Unknown"
                            HostPoolName = $HostPoolName
                        }
                        New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                    }

                    If ($SelfHosted) { Write-Host "." -NoNewline }
                    Else {
                        Show-Menu -Title ("Job Status") -DisplayOnly -Style Info -Color Cyan -ClearScreen
                        $objJob | Format-Table -AutoSize
                        
                        Write-Host "`n`rNext refresh in " -NoNewline
                        Write-Host "15" -ForegroundColor Magenta -NoNewline
                        Write-Host " Seconds`r`n"
                    }
                    If ($stopWatch.Elapsed.TotalMinutes -gt 89) {
                        Write-Warning ("One or More of the Deployment Jobs has exceeded a 90 minutes deployment time!")
                        Break
                    }
                    Start-Sleep -Seconds 15

                } Until ($i -eq 0)
                Write-Host "Done!`n`r"

                $job = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue
                    
                If ($job.ProvisioningState -eq "Succeeded") { $type = "INFO" }
                ElseIf ($job.ProvisioningState -eq "Cancelled") { $type = "WARNING" }
                Else { $type = "ERROR" }

                $logEntry = [PSCustomObject]@{
                    Timestamp = [DateTime]::UtcNow.ToString('o')
                    CorrelationId = $correlationId
                    Computer = $env:COMPUTERNAME
                    UserName = $userName
                    EntryType = $type
                    Subscription = $subscriptionName
                    ResourceGroupName = $ResourceGroupName
                    DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                    DeploymentStatus = $job.ProvisioningState
                    HostPoolName = $HostPoolName
                }
                New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                Disable-AzWvdMaintanence -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -SessionHostGroup $SessionHostGroup -LogAnalyticsResourceGroup $LogAnalyticsResourceGroup -LogAnalyticsWorkspace $LogAnalyticsWorkspace -CorrelationId $correlationId
            }
            Else { Write-Host ("[{0}] WVD Session Host Deployment did not succeed {1}" -f (Get-Date),$Results.ProvisioningState)}
        }
    }
}