Function New-AzWvdDeployment {
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact="Low")]
Param(
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

    [Parameter(Mandatory=$true)]
    [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
    [System.String]$DeploymentResourceGroup,

    [Parameter(Mandatory=$true)]
    [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
    [System.String]$StorageAccountResourceGroup,

    [Parameter(Mandatory=$true)]
    [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Storage/storageAccounts","StorageAccountResourceGroup")]
    [System.String]$StorageAccountName,

    [Parameter(Mandatory=$true)]
    [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.OperationalInsights/workspaces","DeploymentResourceGroup")]
    [System.String]$LogAnalyticsWorkspace,

    [Parameter(Mandatory=$false)]
    [ValidateSet("Pooled","Personal")]
    [System.String]$HostPoolType = "Pooled",

    [Switch]$SelfHosted
)
    BEGIN {
        #Requires -Modules @{ModuleName="Az.DesktopVirtualization"; ModuleVersion="2.0.0"}
        $azContext = Get-AzContext
        
        If ($azContext) {
            Write-Host ("[{0}] Connecting to Azure Cloud..." -f (Get-Date))
            $coreContext = Set-AzContext -Subscription $StorageAccountSubscription
            Write-Host ("`tConnected to: {0}, using {1}" -f $coreContext.Name.Split(" ")[0],$coreContext.Account.Id)
        }
        Else {
            If ($SelfHosted) { $coreContext = Connect-AzAccount -Identity -Subscription $StorageAccountSubscription }
            Else { $coreContext = Connect-AzAccount -Subscription $StorageAccountSubscription }
            Write-Host ("`tConnected to: {0}, using {1}" -f $coreContext.Context.Subscription.Name,$coreContext.Context.Account.Id)
        }

        $userName = ("{0} ({1})" -f $azContext.Account.Id,$azContext.Account.Type)

        If ($SelfHosted) {
            If ($env:COMPUTERNAME -eq "VAC30GHRWVD200" -AND $azContext.Account.Type -eq "ManagedService") {
                $scaleUnitTemplate = ".\Deployment\Deploy-WVD-ScaleUnit.json"
                $scaleUnitParameters = ".\Deployment\Deploy-WVD-ScaleUnit.parameters.json"
            }
            Else {
                Write-Warning ("NOT EXECUTED FROM GITHUB ACTION RUNNER, ABORTING THE OPERATION!")
                Exit
            }
        }
        Else {
            Write-Verbose ("Selecting Scale Unit ARM Template and Parameters file")
            Do {
                Show-Menu -Title "Select Scale Unit ARM Template" -Style Info -Color Cyan -DisplayOnly
                $scaleUnitTemplate = Get-FileNameDialog
                Write-Verbose "`t $scaleUnitTemplate"
                Show-Menu -Title "Select Scale Unit ARM Parameter File" -Style Info -Color Cyan -DisplayOnly
                $scaleUnitParameters = Get-FileNameDialog
                Write-Verbose "`t $scaleUnitParameters"
                If ([system.string]::IsNullOrEmpty($scaleUnitTemplate) -AND [system.string]::IsNullOrEmpty($scaleUnitParameters)) { Write-Warning ("No Scale Unit files selected!") }
                Else { $ValidFile = $true }
            } Until ($ValidFile -eq $true)
        }
    }
    PROCESS {
        Write-Host ("[{0}] Setting up inital variables..." -f (Get-Date))
        $expirationTime = (Get-Date).AddHours(24)        

        Write-Host ("[{0}] Generating Storage SAS Tokens and fetching various URL(s)..." -f (Get-Date))
        $stgAccountContext = (Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroup -DefaultProfile $coreContext).Context
        
        If ($HostPoolType -eq "Pooled") { $wvdHostPoolTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "WindowsVirtualDesktop/Deploy-WVD-HostPool.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri }
        Else { $wvdHostPoolTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "WindowsVirtualDesktop/Deploy-WVD-HostPool-Personal.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri }
        $wvdSessionHostTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "WindowsVirtualDesktop/Deploy-WVD-SessionHosts.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $DscTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob ("WindowsVirtualDesktop/Deploy-WVD-BaselineConfig.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $DscTemplateParamUri = New-AzStorageBlobSASToken -Container templates -Blob ("WindowsVirtualDesktop/Deploy-WVD-BaselineConfig.parameters.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        (New-Object System.Net.WebClient).DownloadFile($DscTemplateParamUri,("{0}\dsc.parameters.json" -f $env:TEMP))
        
        $wvdContext = Set-AzContext -Subscription $subscriptionName
        Write-Host ("`tConnected to: {0}, using {1}" -f $wvdContext.Name.Split("(")[0].Trim(" "),$wvdContext.Account.Id)
        $deploymentParameters = Get-Content $scaleUnitParameters -Raw | ConvertFrom-Json
        $azLogAnalyticsId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $DeploymentResourceGroup -Name $LogAnalyticsWorkspace -WarningAction SilentlyContinue).CustomerId.ToString()
        $azLogAnalyticsKey = (Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $DeploymentResourceGroup -Name $LogAnalyticsWorkspace -WarningAction SilentlyContinue).PrimarySharedKey

        Write-Host ("[{0}] Starting WVD Scale Unit Deployment..." -f (Get-Date))
        $correlationId = [Guid]::NewGuid()
        $deploymentString = $correlationId.Guid.Split("-")[-1]

        $logEntry = [PSCustomObject]@{
            Timestamp = [DateTime]::UtcNow.ToString('o')
            CorrelationId = $correlationId
            Computer = $env:COMPUTERNAME
            UserName = $userName
            EntryType = "INFO"
            Subscription = $subscriptionName
            ResourceGroupName = $DeploymentResourceGroup
            DeploymentName = ("Deploy-WVD-ScaleUnit-{0}" -f $deploymentString)
            DeploymentStatus = "Starting"
            DeploymentType = "ScaleUnit"
            HostPoolName = [System.String]::Empty
        }
        New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false

        Write-Debug "Start Scale Unit"
        $Results = New-AzResourceGroupDeployment `
            -Name ("Deploy-WVD-ScaleUnit-{0}" -f $deploymentString) `
            -ResourceGroupName $DeploymentResourceGroup `
            -wvd_hostPoolTemplateUri $wvdHostPoolTemplateUri `
            -wvd_sessionHostTemplateUri $wvdSessionHostTemplateUri `
            -wvd_deploymentString $deploymentString `
            -TemplateFile $scaleUnitTemplate `
            -TemplateParameterFile $scaleUnitParameters

        If ($Results.ProvisioningState -eq "Succeeded") {
            Write-Host ("[{0}] WVD Scale Unit Deployment Succeeded!" -f $Results.Timestamp.ToLocalTime())
            [PSCustomObject]$Output = $Results.Outputs.Item("hostPoolsDeployed").Value.ToString() | ConvertFrom-Json
            $outputHash = $Output | Group-Object hostPoolName -AsHashTable -AsString

            $logEntry = [PSCustomObject]@{
                Timestamp = [DateTime]::UtcNow.ToString('o')
                CorrelationId = $correlationId
                Computer = $env:COMPUTERNAME
                UserName = $userName
                EntryType = "INFO"
                Subscription = $subscriptionName
                ResourceGroupName = $DeploymentResourceGroup
                DeploymentName = ("Deploy-WVD-ScaleUnit-{0}" -f $deploymentString)
                DeploymentStatus = $Results.ProvisioningState
                DeploymentType = "ScaleUnit"
                HostPoolName = [System.String]::Empty
            }
            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false

            $wvdDscConfigZipUrl = Get-LatestWVDConfigZip -OutputType Local -LocalPath $deploymentParameters.parameters.wvd_hostPoolConfig.value.configs[0].wvdArtifactLocation -Verbose:$false

            [System.Collections.ArrayList]$deploymentJobs = @()
            Foreach ($hostPool in $outputHash.Keys) {

                $dscZipUri = New-AzStorageBlobSASToken -Container dsc -Blob $outputHash[$hostPool].dscConfiguration -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri

                Write-Host ("[{0}] Host Pool: {1} | Generating Host Pool registration token..." -f (Get-Date), $hostPool)
                $wvdHostPoolToken = (Update-AzWvdHostPool -ResourceGroupName $outputHash[$hostPool].resourceGroupName -HostPoolName $HostPool -RegistrationInfoExpirationTime $expirationTime -RegistrationInfoRegistrationTokenOperation Update).RegistrationInfoToken
                #$wvdHostPoolToken = New-AzWvdRegistrationInfo -ResourceGroupName $outputHash[$hostPool].resourceGroupName -HostPoolName $hostPool -ExpirationTime $expirationTime
                $vmNames = Get-AzVm -ResourceGroupName $outputHash[$hostPool].resourceGroupName | ForEach-Object {$_.Name}

                Write-Host ("[{0}] Host Pool: {1} | Starting WVD Session Host Configuration..." -f (Get-Date), $hostPool)

                $logEntry = [PSCustomObject]@{
                    Timestamp = [DateTime]::UtcNow.ToString('o')
                    CorrelationId = $correlationId
                    Computer = $env:COMPUTERNAME
                    UserName = $userName
                    EntryType = "INFO"
                    Subscription = $subscriptionName
                    ResourceGroupName = $outputHash[$hostPool].resourceGroupName
                    DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                    DeploymentStatus = "Starting"
                    DeploymentType = "Configuration"
                    HostPoolName = $hostPool
                }
                New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false

                $templateParams = [Ordered]@{
                    Name = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                    az_virtualMachineNames = $vmNames
                    az_vmImagePublisher = $outputHash[$hostPool].imagePublisher
                    wvd_dscConfigurationScript = $outputHash[$hostPool].dscConfiguration.Trim(".zip")
                    wvd_dscConfigZipUrl = $wvdDscConfigZipUrl
                    wvd_deploymentType = $outputHash[$hostPool].deploymentType
                    wvd_deploymentFunction = $outputHash[$hostPool].deploymentFunction
                    wvd_fsLogixVHDLocation = $outputHash[$hostPool].fsLogixVhdLocation
                    wvd_ArtifactLocation = $outputHash[$hostPool].wvdArtifactLocation
                    wvd_hostPoolName = $hostPool
                    wvd_hostPoolToken = $wvdHostPoolToken
                    wvd_sessionHostDSCModuleZipUri = $dscZipUri
                    ResourceGroupName = $outputHash[$hostPool].resourceGroupName
                    TemplateUri = $DscTemplateUri
                    TemplateParameterFile = ("{0}\dsc.parameters.json" -f $env:TEMP)
                }
                
                Write-Debug ("Start Configuration: {0}" -f $hostPool)
                $deploymentJob = New-AzResourceGroupDeployment @templateParams -AsJob
                While ($true) {
                    $jobInfo = Get-AzResourceGroupDeployment -ResourceGroupName $outputHash[$hostPool].resourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue
                    If ($jobInfo) {Break}
                    Else {
                        Write-Verbose ("[{0}] Waiting for job: Deploy-WVD-DscConfiguration-{1}" -f (Get-Date),$deploymentString)
                        Start-Sleep -Seconds 5
                    }
                }

                $logEntry = [PSCustomObject]@{
                    Timestamp = [DateTime]::UtcNow.ToString('o')
                    CorrelationId = $correlationId
                    Computer = $env:COMPUTERNAME
                    UserName = $userName
                    EntryType = "INFO"
                    Subscription = $subscriptionName
                    ResourceGroupName = $outputHash[$hostPool].resourceGroupName
                    DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                    DeploymentStatus = $jobInfo.ProvisioningState
                    DeploymentType = "Configuration"
                    HostPoolName = $hostPool
                }
                New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                [Void]$deploymentJobs.Add($deploymentJob)
            }

            $currentTime = [DateTime]::UtcNow
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            Do {
                $i = 0
                [System.Collections.Generic.List[System.Object]]$Jobs = @()
                Foreach ($HostPool in $outputHash.Keys) {
                    $deploymentResults = Get-AzResourceGroupDeployment -ResourceGroupName $outputHash[$hostPool].resourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue
                    If ($deploymentResults) {
                        If ($deploymentResults.ProvisioningState -eq "Running") {$i++}
                        $elapsedTime = $deploymentResults.TimeStamp.ToUniversalTime() - $currentTime.ToUniversalTime()
                        $obj = [PSCustomObject][Ordered]@{
                            Name = ("Deploy-WVD-DscConfiguration-{0}  " -f $deploymentString)
                            ResourceGroup = ("{0}  " -f $outputHash[$hostPool].resourceGroupName)
                            Status = ("{0}  " -f $deploymentResults.ProvisioningState)
                            Duration = ("{0:N0}.{1:N0}:{2:N0}:{3:N0}" -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds)
                        }
                        $Jobs.Add($obj)
                    }
                    Else {
                        $i++
                        $obj = [PSCustomObject][Ordered]@{
                            Name = ("Deploy-WVD-DscConfiguration-{0}  " -f $deploymentString)
                            ResourceGroup = ("{0}  " -f $outputHash[$hostPool].resourceGroupName)
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

            Foreach ($HostPool in $outputHash.Keys) {
                $job = Get-AzResourceGroupDeployment -ResourceGroupName $outputHash[$hostPool].resourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue
                
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
                    ResourceGroupName = $outputHash[$hostPool].resourceGroupName
                    DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                    DeploymentStatus = $job.ProvisioningState
                    DeploymentType = "Configuration"
                    HostPoolName = $hostPool
                }
                New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                If ($SelfHosted) { Disable-AzWvdMaintanence -ResourceGroupName $outputHash[$hostPool].resourceGroupName -HostPoolName $hostPool -SessionHostGroup ALL -LogAnalyticsResourceGroup $DeploymentResourceGroup -LogAnalyticsWorkspace $LogAnalyticsWorkspace -CorrelationId $correlationId -SelfHosted }
                Else { Disable-AzWvdMaintanence -ResourceGroupName $outputHash[$hostPool].resourceGroupName -HostPoolName $hostPool -SessionHostGroup ALL -LogAnalyticsResourceGroup $DeploymentResourceGroup -LogAnalyticsWorkspace $LogAnalyticsWorkspace -CorrelationId $correlationId }
            }

        }
        Else {
            Write-Host ("[{0}] WVD Scale Unit Deployment did not succeed - State: {1}" -f (Get-Date),$Results.ProvisioningState)
            $logEntry = [PSCustomObject]@{
                Timestamp = [DateTime]::UtcNow.ToString('o')
                CorrelationId = $correlationId
                Computer = $env:COMPUTERNAME
                UserName = $userName
                EntryType = "ERROR"
                Subscription = $subscriptionName
                ResourceGroupName = $DeploymentResourceGroup
                DeploymentName = ("Deploy-WVD-ScaleUnit-{0}" -f $deploymentString)
                DeploymentStatus = $Results.ProvisioningState
                DeploymentType = "ScaleUnit"
                HostPoolName = $null
            }
            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
        }
    }
}