Function New-AzWvdDeployment {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low")]
    Param(
        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( {
                Param($CommandName, $ParameterName, $WordsToComplete, $CommandAst, $FakeBoundParameters)
                Get-AzSubscription | Where-Object { $_.Name -like "$WordsToComplete*" } | Select-Object -ExpandProperty Name
            })]
        [System.String]$SubscriptionName,

        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( {
                Param($CommandName, $ParameterName, $WordsToComplete, $CommandAst, $FakeBoundParameters)
                Get-AzSubscription | Where-Object { $_.Name -like "$WordsToComplete*" } | Select-Object -ExpandProperty Name
            })]
        [System.String]$StorageAccountSubscription,

        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( {
                Param($CommandName, $ParameterName, $WordsToComplete, $CommandAst, $FakeBoundParameters)
                Get-AzEnvironment | Where-Object { $_.Name -like "$WordsToComplete*" } | Select-Object -ExpandProperty Name
            })]
        [System.String]$AzureEnvironment,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$DeploymentResourceGroup,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$StorageAccountResourceGroup,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Storage/storageAccounts", "StorageAccountResourceGroup")]
        [System.String]$StorageAccountName,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.OperationalInsights/workspaces", "DeploymentResourceGroup")]
        [System.String]$LogAnalyticsWorkspace,

        [Switch]$EnablePostConfiguration
    )
    BEGIN {
        #Requires -Modules @{ModuleName="Az.DesktopVirtualization"; ModuleVersion="2.0.0"}
        $wvdContext = Get-AzContext
        
        If ($wvdContext) {
            Write-Host ("[{0}] Creating new Context to Storage Account Subscription ({1} in {2})..." -f (Get-Date),$wvdContext.Subscription.Name,$wvdContext.Environment.Name)
            $stgContext = Set-AzContext -Subscription $StorageAccountSubscription
            Write-Host ("`tConnected to: {0}, using {1}" -f $stgContext.Subscription.Name, $stgContext.Account.Id)
        }
        Else {
            $stgContext = Connect-AzAccount -Subscription $StorageAccountSubscription -Environment $AzureEnvironment
            Write-Host ("`tConnected to: {0} in ({1}), using {2}" -f $stgContext.Subscription.Name,$stgContext.Environment.Name,$stgContext.Account.Id)
        }

        Write-Verbose ("Selecting Scale Unit ARM Template and Parameters file")
        Do {
            Show-Menu -Title "Select Scale Unit ARM Template" -Style Info -Color Cyan -DisplayOnly
            $scaleUnitTemplate = Get-FileNameDialog -InitialDirectory (Get-Location).Path -Filter "ARM JSON (*.json)| *.json"
            Write-Verbose "`t $scaleUnitTemplate"
            Show-Menu -Title "Select Scale Unit ARM Parameter File" -Style Info -Color Cyan -DisplayOnly
            $scaleUnitParameters = Get-FileNameDialog -InitialDirectory (Get-Location).Path -Filter "ARM JSON (*.json)| *.json"
            Write-Verbose "`t $scaleUnitParameters"
            If ([system.string]::IsNullOrEmpty($scaleUnitTemplate) -AND [system.string]::IsNullOrEmpty($scaleUnitParameters)) { Write-Warning ("No Scale Unit files selected!") }
            Else { $ValidFile = $true }
        } Until ($ValidFile -eq $true)
    }
    PROCESS {
        Write-Host ("[{0}] Setting up inital variables..." -f (Get-Date))
        $expirationTime = (Get-Date).AddHours(24)        

        Write-Host ("[{0}] Generating Storage SAS Tokens and fetching various URL(s)..." -f (Get-Date))
        $stgAccountContext = (Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroup -DefaultProfile $stgContext).Context
        try {
            $wvdHostPoolTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "Deploy-WVD-HostPool.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
            $wvdSessionHostTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "Deploy-WVD-SessionHosts.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
            If ($EnablePostConfiguration) {
                $DscTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob ("Deploy-WVD-Config.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
                $DscTemplateParamUri = New-AzStorageBlobSASToken -Container templates -Blob ("Deploy-WVD-Config.parameters.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
                (New-Object System.Net.WebClient).DownloadFile($DscTemplateParamUri, ("{0}\dsc.parameters.json" -f $env:TEMP))
            }
                
            $wvdContext = Set-AzContext -Subscription $subscriptionName
            Write-Host ("`tConnected to: {0} in ({1}), using {2}" -f $wvdContext.Subscription.Name,$wvdContext.Environment.Name,$wvdContext.Account.Id)
            $deploymentParameters = Get-Content $scaleUnitParameters -Raw | ConvertFrom-Json
            If (-NOT (Get-AzWvdWorkspace -Name $deploymentParameters.parameters.wvd_workspaceName.value -ResourceGroupName $DeploymentResourceGroup -ErrorAction SilentlyContinue)) {
                Write-Warning ("WVD Workspace: {0} - NOT FOUND, creating workspace!" -f $deploymentParameters.parameters.wvd_workspaceName.value)
                $wvdWorkspace = New-AzWvdWorkspace -Name $deploymentParameters.parameters.wvd_workspaceName.value -ResourceGroupName $DeploymentResourceGroup -Location (Get-AzResourceGroup -Name $DeploymentResourceGroup).Location
                If ($wvdWorkspace) { Write-Host ("[{0}] WVD Workspace created successfully!" -f (Get-Date)) -ForegroundColor Green }
                Else {
                    $PSCmdlet.ThrowTerminatingError(
                        [System.Management.Automation.ErrorRecord]::New(
                            [System.SystemException]::New("Failed to create WVD Workspace"),
                            "FailedWorkspaceCreation",
                            [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                            ("WVD Workspace: {0}" -f $deploymentParameters.parameters.wvd_workspaceName.value)
                        )
                    )
                }
            }
        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }

        $azLogAnalyticsId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $DeploymentResourceGroup -Name $LogAnalyticsWorkspace -WarningAction SilentlyContinue).CustomerId.ToString()
        $azLogAnalyticsKey = (Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $DeploymentResourceGroup -Name $LogAnalyticsWorkspace -WarningAction SilentlyContinue).PrimarySharedKey

        Write-Host ("[{0}] Starting WVD Scale Unit Deployment..." -f (Get-Date))
        $correlationId = [Guid]::NewGuid()
        $deploymentString = $correlationId.Guid.Split("-")[-1]

        $logEntry = [PSCustomObject]@{
            Timestamp         = [DateTime]::UtcNow.ToString('o')
            CorrelationId     = $correlationId
            Computer          = $env:COMPUTERNAME
            UserName          = $wvdContext.Account.Id
            EntryType         = "INFO"
            Subscription      = $subscriptionName
            ResourceGroupName = $DeploymentResourceGroup
            DeploymentName    = ("Deploy-WVD-ScaleUnit-{0}" -f $deploymentString)
            DeploymentStatus  = "Starting"
            DeploymentType    = "ScaleUnit"
            HostPoolName      = [System.String]::Empty
        }
        New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false

        Write-Debug "Start Scale Unit"
        $Results = New-AzResourceGroupDeployment `
            -Name ("Deploy-WVD-ScaleUnit-{0}" -f $deploymentString) `
            -ResourceGroupName $DeploymentResourceGroup `
            -wvd_hostPoolTemplateUri $wvdHostPoolTemplateUri `
            -wvd_sessionHostTemplateUri $wvdSessionHostTemplateUri `
            -wvd_deploymentString $deploymentString `
            -wvd_deploymentGuid $correlationId.guid `
            -TemplateFile $scaleUnitTemplate `
            -TemplateParameterFile $scaleUnitParameters

        If ($Results.ProvisioningState -eq "Succeeded") {
            Write-Host ("[{0}] WVD Scale Unit Deployment Succeeded!" -f $Results.Timestamp.ToLocalTime())

            $logEntry = [PSCustomObject]@{
                Timestamp         = [DateTime]::UtcNow.ToString('o')
                CorrelationId     = $correlationId
                Computer          = $env:COMPUTERNAME
                UserName          = $wvdContext.Account.Id
                EntryType         = "INFO"
                Subscription      = $subscriptionName
                ResourceGroupName = $DeploymentResourceGroup
                DeploymentName    = ("Deploy-WVD-ScaleUnit-{0}" -f $deploymentString)
                DeploymentStatus  = $Results.ProvisioningState
                DeploymentType    = "ScaleUnit"
                HostPoolName      = [System.String]::Empty
            }
            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
        }
        Else {
            Write-Host ("[{0}] WVD Scale Unit Deployment did not succeed - State: {1}" -f (Get-Date), $Results.ProvisioningState)
            $logEntry = [PSCustomObject]@{
                Timestamp         = [DateTime]::UtcNow.ToString('o')
                CorrelationId     = $correlationId
                Computer          = $env:COMPUTERNAME
                UserName          = $wvdContext.Account.Id
                EntryType         = "ERROR"
                Subscription      = $subscriptionName
                ResourceGroupName = $DeploymentResourceGroup
                DeploymentName    = ("Deploy-WVD-ScaleUnit-{0}" -f $deploymentString)
                DeploymentStatus  = $Results.ProvisioningState
                DeploymentType    = "ScaleUnit"
                HostPoolName      = $null
            }
            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
        }
    }
}