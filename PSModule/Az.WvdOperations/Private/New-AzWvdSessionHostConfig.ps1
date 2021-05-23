Function New-AzWvdSessionHostConfig {
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

        # Group of Session Hosts to target (A or B)
        [Parameter(Mandatory=$true)]
        [ValidateSet("A","B","ALL")]
        [String]$SessionHostGroup,

        # Name of the Resource Group of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$StorageAccountResourceGroup,

        # Name of the WVD Artifact Blob Storage Account (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Storage/storageAccounts","StorageAccountResourceGroup")]
        [System.String]$StorageAccountName,

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
        $wvdContext = Set-AzContext -Subscription $subscriptionName
        Write-Host ("`tConnected to: {0}, using {1}" -f $wvdContext.Name.Split("(")[0].Trim(" "),$wvdContext.Account.Id)
        # $expirationTime = (Get-Date).AddHours(12)
        # $wvdConfigZipPath = "\\vac30hsm01-6833.va.gov\vac30-wvd-netapp-pool01-vol01\wvdartifacts\Deployments"
        # $coreAzContext = Set-AzContext -Subscription $StorageAccountSubscription
        # $stgAccountContext = (Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroup -DefaultProfile $coreAzContext).Context
        # $wvdDscConfigZipUrl = Get-LatestWVDConfigZip -OutputType Local -LocalPath $wvdConfigZipPath -Verbose:$false

    }
    PROCESS {
        
        [System.Collections.Generic.List[Object]]$deploymentJobs = @()
        Write-Host ("[{0}] Setting up inital variables..." -f (Get-Date))
        $expirationTime = (Get-Date).AddHours(24)
        $correlationId = [Guid]::NewGuid()
        $deploymentString = ([Guid]::NewGuid()).Guid.Split("-")[-1]    

        Write-Host ("[{0}] Generating Storage SAS Tokens and fetching various URL(s)..." -f (Get-Date))
        $stgAccountContext = (Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroup -DefaultProfile $coreContext).Context

        $DscTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob ("WindowsVirtualDesktop/Deploy-WVD-BaselineConfig.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $DscTemplateParamUri = New-AzStorageBlobSASToken -Container templates -Blob ("WindowsVirtualDesktop/Deploy-WVD-BaselineConfig.parameters.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        (New-Object System.Net.WebClient).DownloadFile($DscTemplateParamUri,("{0}\dsc.parameters.json" -f $env:TEMP))
        
        $azLogAnalyticsId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspace -WarningAction SilentlyContinue).CustomerId.ToString()
        $azLogAnalyticsKey = (Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspace -WarningAction SilentlyContinue).PrimarySharedKey
        
        Do {
            Write-Verbose "Getting WVD Host Pools..."
            $HPs = Get-AzWvdHostPool -Verbose:$false -Debug:$false | Select-Object @{l="Name";e={$_.Name.Split("/")[-1]}},@{l="ResourceGroupName";e={$_.Id.Split("/")[4]}},Tag,VMTemplate
            Write-Verbose ("Found {0} Azure WVD Host Pools" -f $HPs.Count)
            $HPSelection = ""
            $HPRange = 1..($HPs.Count)
            For ($i = 0; $i -lt $HPs.Count;$i++) {$HPSelection += (" [{0}] {1}`n" -f ($i+1),$HPs[$i].Name)}
            $HPSelection += "`n Please select a Host Pool or [Q] to Quit"

            Do {
                If ($HPChoice -eq "Q") { Return }
                $HPChoice = Show-Menu -Title "Select an Azure WVD Host Pool" -Menu $HPSelection -Style Full -Color White -ClearScreen
            }
            While (($HPRange -notcontains $HPChoice) -OR (-NOT $HPChoice.GetType().Name -eq "Int32"))
            $HPChoice = $HPChoice - 1

            Clear-Host
            Write-Host ("[{0}] Host Pool: {1}" -f (Get-Date),$HPs[$HPChoice].Name)
            Write-Host ("[{0}] Host Pool: {1} | Generating Host Pool registration token and fetch Configuration URL(s)" -f (Get-Date),$HPs[$HPChoice].Name)

            #$correlationId = [Guid]::NewGuid()
            #$deploymentString = ([Guid]::NewGuid()).Guid.Split("-")[-1]
            $DscConfiguration = $HPs[$HPChoice].Tag["WVD-DscConfiguration"]
            $FsLogixVhdLocation = $HPs[$HPChoice].Tag["WVD-FsLogixVhdLocation"]
            $vmTemplate = $HPs[$HPChoice].VMTemplate | ConvertFrom-Json
            $wvdDscConfigZipUrl = Get-LatestWVDConfigZip -OutputType Local -LocalPath $HPs[$HPChoice].Tag["WVD-ArtifactLocation"] -Verbose:$false
            $dscZipUri = New-AzStorageBlobSASToken -Container dsc -Blob $DscConfiguration -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
            #$DscTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob ("WindowsVirtualDesktop/Deploy-WVD-BaselineConfig.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
            #$DscTemplateParamUri = New-AzStorageBlobSASToken -Container templates -Blob ("WindowsVirtualDesktop/Deploy-WVD-BaselineConfig.parameters.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
            #(New-Object System.Net.WebClient).DownloadFile($DscTemplateParamUri,("{0}\dsc.parameters.json" -f $env:TEMP))
            $wvdHostPoolToken = (Update-AzWvdHostPool -ResourceGroupName $HPs[$HPChoice].ResourceGroupName -Name $HPs[$HPChoice].Name -RegistrationInfoExpirationTime $expirationTime -RegistrationInfoRegistrationTokenOperation Update).RegistrationInfoToken
            #$wvdHostPoolToken = New-AzWvdRegistrationInfo -ResourceGroupName $HPs[$HPChoice].ResourceGroupName -HostPoolName $HPs[$HPChoice].Name -ExpirationTime $expirationTime
            If ($SessionHostGroup -eq "A") {
                $vmNames = Get-AzVm -ResourceGroupName $HPs[$HPChoice].ResourceGroupName | Where-Object {$_.Tags["WVD-Group"] -eq "A"} | ForEach-Object {$_.Name}
                $deploymentName = ("Deploy-WVD-DscConfiguration-Group-{0}-{1}" -f $SessionHostGroup,$deploymentString)
            }
            If ($SessionHostGroup -eq "B") {
                $vmNames = Get-AzVm -ResourceGroupName $HPs[$HPChoice].ResourceGroupName | Where-Object {$_.Tags["WVD-Group"] -eq "B"} | ForEach-Object {$_.Name}
                $deploymentName = ("Deploy-WVD-DscConfiguration-Group-{0}-{1}" -f $SessionHostGroup,$deploymentString)
            }
            If ($SessionHostGroup -eq "ALL") {
                $vmNames = Get-AzVm -ResourceGroupName $HPs[$HPChoice].ResourceGroupName | ForEach-Object {$_.Name}
                $deploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
            }
        
            #Write-Host ("Host Pool: {0} | Starting WVD Session Host Configuration (AsJob)..." -f $HPs[$HPChoice].Name)
            Write-Host ("[{0}] Host Pool: {1} | Starting WVD Session Host Configuration..." -f (Get-Date), $HPs[$HPChoice].Name)
            $logEntry = [PSCustomObject]@{
                Timestamp = [DateTime]::UtcNow.ToString('o')
                CorrelationId = $correlationId
                Computer = $env:COMPUTERNAME
                UserName = $userName
                EntryType = "INFO"
                Subscription = $subscriptionName
                ResourceGroupName = $HPs[$HPChoice].ResourceGroupName
                DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                DeploymentStatus = "Starting"
                HostPoolName = $HostPoolName
            }
            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
            
            $templateParams = [Ordered]@{
                Name = $deploymentName
                az_virtualMachineNames = $vmNames
                az_vmImagePublisher = $vmTemplate.galleryImagePublisher
                wvd_dscConfigurationScript = $DscConfiguration.Trim(".zip")
                wvd_dscConfigZipUrl = $wvdDscConfigZipUrl
                wvd_deploymentType = $HPs[$HPChoice].Tag["WVD-Deployment"]
                wvd_deploymentFunction = $HPs[$HPChoice].Tag["WVD-Function"]
                wvd_fsLogixVHDLocation = $FsLogixVhdLocation
                wvd_ArtifactLocation = $HPs[$HPChoice].Tag["WVD-ArtifactLocation"]
                wvd_hostPoolName = $HPs[$HPChoice].Name
                wvd_hostPoolToken = $wvdHostPoolToken
                wvd_sessionHostDSCModuleZipUri = $dscZipUri
                ResourceGroupName = $HPs[$HPChoice].ResourceGroupName
                TemplateUri = $DscTemplateUri
                TemplateParameterFile = ("{0}\dsc.parameters.json" -f $env:TEMP)
            }

            If ($PSCmdlet.ShouldProcess($HPs[$HPChoice].Name,"Initiate DSC Configuration Deployment")) {
                $deploymentJob = New-AzResourceGroupDeployment @templateParams -AsJob
                If ($deploymentJob) {
                    $deploymentJobs.Add($HPs[$HPChoice])
                    Write-Host ("Active Deployment Jobs: {0}" -f (Get-Job -State Running).Count)
                    try {
                        While ($true) {
                            If (Get-AzResourceGroupDeployment -ResourceGroupName $HPs[$HPChoice].ResourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue) { Break }
                            Else {
                                Write-Verbose ("[{0}] Waiting for job: Deploy-WVD-DscConfiguration-{1}" -f (Get-Date),$deploymentString)
                                Start-Sleep -Seconds 5
                            }
                        }
    
                        $deploymentInfo = Get-AzResourceGroupDeployment -ResourceGroupName $HPs[$HPChoice].ResourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                        $logEntry = [PSCustomObject]@{
                            Timestamp = [DateTime]::UtcNow.ToString('o')
                            CorrelationId = $correlationId
                            Computer = $env:COMPUTERNAME
                            UserName = $userName
                            EntryType = "INFO"
                            Subscription = $subscriptionName
                            ResourceGroupName = $HPs[$HPChoice].ResourceGroupName
                            DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                            DeploymentStatus = $deploymentInfo.ProvisioningState
                            HostPoolName = $HPs[$HPChoice].Name
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
                            ResourceGroupName = $HPs[$HPChoice].ResourceGroupName
                            DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                            DeploymentStatus = $_.Exception.Message
                            HostPoolName = $HPs[$HPChoice].Name
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
                        ResourceGroupName = $HPs[$HPChoice].ResourceGroupName
                        DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                        DeploymentStatus = "NotStarted"
                        HostPoolName = $HPs[$HPChoice].Name
                    }
                    New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                    Break
                }
            }
            Else {Write-Host "Configuration cancelled!"}
            $Done = Get-ChoicePrompt -Title "`n" -Message "Select another WVD Host Pool Group?" -OptionList "&Yes","&No"
        } Until ($Done -eq 1)

        $currentTime = [DateTime]::UtcNow
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        Do {
            $i = 0
            [System.Collections.Generic.List[System.Object]]$Jobs = @()
            Foreach ($HostPool in $deploymentJobs) {
                $deploymentResults = Get-AzResourceGroupDeployment -ResourceGroupName $HostPool.resourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue
                If ($deploymentResults) {
                    If ($deploymentResults.ProvisioningState -eq "Running") {$i++}
                    $elapsedTime = $deploymentResults.TimeStamp.ToUniversalTime() - $currentTime
                    $obj = [PSCustomObject][Ordered]@{
                        Name = ("Deploy-WVD-DscConfiguration-{0}  " -f $deploymentString)
                        ResourceGroup = ("{0}  " -f $HostPool.resourceGroupName)
                        Status = ("{0}  " -f $deploymentResults.ProvisioningState)
                        Duration = ("{0:N0}.{1:N0}:{2:N0}:{3:N0}" -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds)
                    }
                    $Jobs.Add($obj)
                }
                Else {
                    $i++
                    $obj = [PSCustomObject][Ordered]@{
                        Name = ("Deploy-WVD-DscConfiguration-{0}  " -f $deploymentString)
                        ResourceGroup = ("{0}  " -f $HostPool.resourceGroupName)
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
            If ($stopWatch.Elapsed.TotalMinutes -gt 89) { Write-Warning ("One or More of the Deployment Jobs has exceeded 90 minutes deployment time!") }
            Start-Sleep -Seconds 15

        } Until ($i -eq 0)
        Write-Host "Done!`n`r"

        Foreach ($HostPool in $deploymentJobs) {
            $job = Get-AzResourceGroupDeployment -ResourceGroupName $HostPool.resourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue
            
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
                ResourceGroupName = $HostPool.resourceGroupName
                DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                DeploymentStatus = $job.ProvisioningState
                DeploymentType = "Configuration"
                HostPoolName = $HostPool.Name
            }
            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
        }
    }
}