Function New-AzAvdDeployment {
    <#
        .SYNOPSIS
            TO DO
        .DESCRIPTION
            TO DO
    #>
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
    Param(
        # Resource Group where the AVD Workspace, Host Pools, and Application Groups reside; based on environment and region
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$ResourceGroupName,

        # Storage Account Name for the AVD artifacts
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Storage/storageAccounts","ResourceGroupName")]
        [System.String]$StorageAccountName,

        # Switch parameter used when deployed via a Managed Service Identity (GitHub Runner, Hybrid Runbook Worker, etc..)
        [Switch]$SelfHostedRunner
    )
    BEGIN {
        #Requires -Modules @{ModuleName="Az.DesktopVirtualization"; ModuleVersion="3.0.0"}
        Show-Menu -Title $PSCmdlet.MyInvocation.MyCommand.Name -Style Full -Color White -DisplayOnly
        Get-AzAuthentication
        Write-Verbose ("{0} - AzAuthentication - {1} Connected to {2} ({3})" -f (Get-Date).ToLongTimeString(),$SCRIPT:AzAuthentication.Account.Id,$SCRIPT:AzAuthentication.Subscription.Name,$SCRIPT:AzAuthentication.Subscription.Id)

        If ($SelfHostedRunner) {
            If ($SCRIPT:AzAuthentication.Account.Type -eq "ManagedService") {
                #$scaleUnitTemplate = ("{0}\{1}\Deployment\Deploy-WVD-ScaleUnit.json" -f $env:GITHUB_WORKSPACE, $env:BRANCH)
                #$scaleUnitParameters = ("{0}\{1}\Deployment\Deploy-WVD-ScaleUnit.parameters.json" -f $env:GITHUB_WORKSPACE, $env:BRANCH)
                #$GitBranch = $env:BRANCH
            }
            Else {
                Write-Warning ("NOT EXECUTED FROM GITHUB ACTION RUNNER, ABORTING THE OPERATION!")
                Exit
            }
        }
        Else {
            Write-Verbose ("{0} - Selecting AVD Unified Deployment ARM Template and Parameter files" -f (Get-Date).ToLongTimeString())
            Show-Menu -Title "Select AVD Unified Deployment ARM Template" -Style Info -Color Cyan -DisplayOnly
            $unifiedTemplate = Get-FileNameDialog -Filter "Json Files (*.json)|*.json|Bicep Files (*.bicep)|*.bicep"
            Show-Menu -Title "Select AVD Unified Deployment ARM Parameter File" -Style Info -Color Cyan -DisplayOnly
            $unifiedParameters = Get-FileNameDialog -Filter "Json Files (*.json)|*.json|Bicep Files (*.bicep)|*.bicep"
            If ([system.string]::IsNullOrEmpty($unifiedTemplate) -OR [system.string]::IsNullOrEmpty($unifiedParameters)) {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::New(
                        [System.SystemException]::New(("One or more Unified Deployment files were not selected!")),
                        "TemplateFilesNotFound",
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        ("AVD Unified Deployment Templates")
                    )
                )
            }
            Else {
                $correlationId = [Guid]::NewGuid().ToString()
                $avdSubscriptionId = Get-Content -Path $unifiedParameters -raw | ConvertFrom-Json | ForEach-Object {$_.parameters.avd_subscriptionid.value}
                Write-Verbose ("{0} - TemplateFile: $unifiedTemplate" -f (Get-Date).ToLongTimeString())
                Write-Verbose ("{0} - ParameterFile: $unifiedParameters" -f (Get-Date).ToLongTimeString())
                Write-Verbose ("{0} - Deployment String: $correlationId" -f (Get-Date).ToLongTimeString())
            }

            # Do {
            #     $GitBranch = Show-Menu -Title "Developer Workspace Selection" -Menu ("`nPlease provide the name of the devspace you're working in for this deployment") -Style Info -Color Cyan
            #     $Done = Get-ChoicePrompt -Title "Developer Workspace" -Message ("Is ['{0}'] the correct devspace?" -f $GitBranch.ToLower()) -OptionList "&Yes","&No" -Default 1
            # } Until ($Done -eq 0)
        }
    }
    PROCESS {
        Write-Host ("INFO:    {0} - Setting up inital variables..." -f (Get-Date).ToLongTimeString())
        $expirationTime = (Get-Date).AddHours(24)

        Write-Host ("INFO:    {0} - Generating Storage SAS Tokens and fetching various URL(s)..." -f (Get-Date).ToLongTimeString())
        $stgAccountContext = (Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName).Context

        $avdVirtualMachineTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob ("ACS-VirtualMachine-Deployment.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $avdExtensionTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob ("ACS-Extension-Deployment.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri

        Write-Host ("INFO:    {0} - Starting AVD Unified Deployment..." -f (Get-Date).ToLongTimeString())
        $Results = New-AzResourceGroupDeployment `
            -Name ("ACS-UnifiedDeployment-{0}" -f $correlationId.Split("-")[-1]) `
            -ResourceGroupName $ResourceGroupName `
            -avd_VirtualMachineTemplateUri $avdVirtualMachineTemplateUri `
            -avd_deploymentGuid $correlationId `
            -TemplateFile $unifiedTemplate `
            -TemplateParameterFile $unifiedParameters

        If ($Results.ProvisioningState -eq "Succeeded") {
            Write-Host ("INFO:    {0} - ACS Unified Deployment Succeeded!" -f (Get-Date).ToLongTimeString())
            [PSCustomObject]$Output = $Results.Outputs["avdDeployedVirtualMachines"].Value.ToString() | ConvertFrom-Json
            $vmRgCollection = $Output | Group-Object vmResourceGroup -AsHashTable -AsString

            # $DebugPreference = "inquire"
            # Write-Debug "Post Deploy Check"
            # $DebugPreference = "silentlycontinue"

            $avdLaWorkspaceId = Get-AzKeyVaultSecret -ResourceId ($Output.azKeyVaultId | Select-Object -First 1) -Name "ACS-MAP-LogAnlaytics-Id" -AsPlainText
            $avdLaWorkspaceKey = Get-AzKeyVaultSecret -ResourceId ($Output.azKeyVaultId | Select-Object -First 1) -Name "ACS-MAP-LogAnlaytics-Key" -AsPlainText
            $avdAdminAccount = Get-AzKeyVaultSecret -ResourceId ($Output.azKeyVaultId | Select-Object -First 1) -Name AVDSvcAcctUsername -AsPlainText
            $avdAdminPassword = Get-AzKeyVaultSecret -ResourceId ($Output.azKeyVaultId | Select-Object -First 1) -Name AVDSvcAcctPassword -AsPlainText

            try {
                If ($SCRIPT:AzAuthentication.Subscription.Id -eq $avdSubscriptionId) { Write-Host ("INFO:    {0} - AzAuthentication and AVD SubscriptionId ({1}) MATCH" -f (Get-Date).ToLongTimeString(),$avdSubscriptionId) }
                Else {
                    $avdContext = $null
                    If ( Get-AzContext -ListAvailable | Where-Object { $_.Subscription.Id -eq $avdSubscriptionId } ) {
                        $avdContext = Get-AzContext -ListAvailable | Where-Object { $_.Subscription.Id -eq $avdSubscriptionId } | Set-AzContext
                        Write-Verbose ("{0} - Connected to {1} ({2}) in AzureCloud" -f (Get-Date).ToLongTimeString(),$avdContext.Subscription.Name,$avdContext.Subscription.Id)
                    }
                    Else {
                        Write-Host ("INFO:    {0} - Checking Azure Cloud Environment" -f (Get-Date))
                        If ($SCRIPT:AzAuthentication.Environment.Name -eq "AzureUSGovernment") {
                            Write-Warning ("Connected in AzureUSGovernment, Switching to AzureCloud...")
                            If ($SCRIPT:AzAuthentication.Account.Type -eq "ManagedService") { $avdContext = Connect-AzAccount -Environment AzureCloud -Subscription $avdSubscriptionId -Identity }
                            Else { $avdContext = Connect-AzAccount -Environment AzureCloud -Subscription $avdSubscriptionId }
                            Write-Verbose ("{0} - Connected to {1} ({2}) in AzureCloud" -f (Get-Date).ToLongTimeString(),$avdContext.Subscription.Name,$avdContext.Subscription.Id)
                        }
                        Else {
                            Write-Verbose ("{0} - Connected in AzureCloud" -f (Get-Date).ToLongTimeString())
                            If ( [System.Boolean](Get-AzSubscription -SubscriptionId $avdSubscriptionId) ) {
                                $avdContext = Get-AzSubscription -SubscriptionId $avdSubscriptionId | Set-AzContext
                            }
                            Else {
                                Write-Verbose ("{0} - Azure Virtual Desktop Subscription not found!" -f (Get-Date).ToLongTimeString())
                                $PSCmdlet.ThrowTerminatingError(
                                    [System.Management.Automation.ErrorRecord]::New(
                                        [System.SystemException]::New(("Subscription not found")),
                                        "SubscriptionNotFound",
                                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                                        ("AVD Subscription Id: {0}" -f $avdSubscriptionId)
                                    )
                                )
                            }
                        }
                    }
                }
            }
            catch { $PSCmdlet.ThrowTerminatingError($PSItem) }

            $vmRgCollection.Keys | Foreach-Object {
                $HostPoolToken = $null
                $HostPoolName = $vmRgCollection[$_].HostPoolName
                Write-Host ("INFO:    {0} - VM Deployment: {1} | Generating Host Pool registration token..." -f (Get-Date).ToLongTimeString(),$_)
                $avdHostPool = Get-AzWvdHostPool | Where-Object {$_.Name -eq $HostPoolName}
                $avdResourceGroup = $avdHostPool.Id.Split("/")[4]
                $TokenProperties = Get-AzWvdHostPoolRegistrationToken -ResourceGroupName $avdResourceGroup -HostPoolName $HostPoolName
                If ( [System.Boolean]($TokenProperties.ExpirationTime) ) {
                    Write-Warning ("{0} - Found Token expiration time, checking if time has expired" -f (Get-Date).ToLongTimeString())
                    If ($TokenProperties.ExpirationTime.ToLocalTime() -gt (Get-Date).AddHours(2)) {
                        $TokenExpiration = $TokenProperties.ExpirationTime.ToLocalTime() - (Get-Date)
                        Write-Host ("INFO:    {0} - Current Host Pool Token is valid for another {1} hours and {2} minutes" -f (Get-Date).ToLongTimeString(),$TokenExpiration.Hours,$TokenExpiration.minutes)
                        Write-Host ("`t Using current Host Pool Token for Session Host Registration") -ForegroundColor Green
                        $HostPoolToken = $TokenProperties.Token
                    }
                    Else {
                        Write-Warning ("{0} - Token is expired or about to expire soon" -f (Get-Date).ToLongTimeString())
                        $HostPoolToken = (Update-AzWvdHostPool `
                            -ResourceGroupName $avdResourceGroup `
                            -Name $HostPoolName `
                            -RegistrationInfoExpirationTime $expirationTime `
                            -RegistrationInfoRegistrationTokenOperation Update).RegistrationInfoToken
                        If ($HostPoolToken) { Write-Host ("INFO:    {0} - Generated a new registration token for {1} (Expires: {2})" -f (Get-Date).ToLongTimeString(),$HostPoolName,$expirationTime.ToLocalTime()) }
                    }
                }
                Else {
                    Write-Warning ("{0} - No Token or Token Expiration found" -f (Get-Date).ToLongTimeString())
                    $HostPoolToken = (Update-AzWvdHostPool `
                        -ResourceGroupName $avdResourceGroup `
                        -Name $HostPoolName `
                        -RegistrationInfoExpirationTime $expirationTime `
                        -RegistrationInfoRegistrationTokenOperation Update).RegistrationInfoToken
                    If ($HostPoolToken) { Write-Host ("INFO:    {0} - Generated a new registration token for {1} (Expires: {2}" -f (Get-Date).ToLongTimeString(),$HostPoolName,$expirationTime.ToLocalTime()) }
                }
                $vmRgCollection[$_] | Add-Member -NotePropertyName HostPoolToken -NotePropertyValue $HostPoolToken
            }

            If ( $PSCmdlet.ShouldProcess(("{0} VM Deployment(s)" -f $vmRgCollection.Keys.Count),"Start AVD Extension Deployment(s)") ) {
                [System.Collections.ArrayList]$deploymentJobs = @()
                Foreach ($vmDeployment in $vmRgCollection.Keys) {
                    $SCRIPT:AzAuthentication | Set-AzContext | Out-Null
                    Write-Host ("INFO:    {0} - Fetching AVD Blob URL(s) from ACS Artifact Storage Account ({1})" -f (Get-Date).ToLongTimeString(),$StorageAccountName)
                    [PSCustomObject]$avdBlobURLs = [Ordered]@{
                        DscConfigurationZip = New-AzStorageBlobSASToken -Container dsc -Blob ("{0}.zip" -f $vmRgCollection[$vmDeployment].dscConfigurationScript) -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
                        AvdBaselinePackages = New-AzStorageBlobSASToken -Container apps -Blob ("baseline_avd_packages.zip") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
                        Avd1vaPackages = New-AzStorageBlobSASToken -Container apps -Blob ("1va_avd_packages.zip") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
                        AvdAdmPackages = New-AzStorageBlobSASToken -Container apps -Blob ("adm_avd_packages.zip") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
                        AvdCanaryPackages = New-AzStorageBlobSASToken -Container apps -Blob ("canary_avd_packages.zip") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
                    }

                    $vmContext = $null
                    If (@(Get-AzContext).Subscription.Id -eq $vmRgCollection[$vmDeployment].vmSubscriptionId) {
                        $vmContext = Get-AzContext
                        Write-Host ("INFO:    {0} - Current Azure Context matches Virtual Machine Deployment Subscription Id" -f (Get-Date).ToLongTimeString())
                    }
                    Else {
                        If ( Get-AzContext -ListAvailable | Where-Object { $_.Subscription.Id -eq $vmRgCollection[$vmDeployment].vmSubscriptionId } ) {
                            $vmContext = Get-AzContext -ListAvailable | Where-Object { $_.Subscription.Id -eq $vmRgCollection[$vmDeployment].vmSubscriptionId } | Set-AzContext
                        }
                        Else {
                            If ( [System.Boolean](Get-AzSubscription -SubscriptionId $vmRgCollection[$vmDeployment].vmSubscriptionId) ) {
                                $vmContext = Get-AzSubscription -SubscriptionId $vmRgCollection[$vmDeployment].vmSubscriptionId | Set-AzContext
                            }
                            Else {
                                Write-Warning ("Unable to locate or no access to VM Subscription: {0}" -f $vmRgCollection[$vmDeployment].vmSubscriptionId)
                                Break
                            }
                        }
                        Write-Host ("INFO:    {0} - Connected to {1} ({2}) for Virtual Machine Deployment ({3})" -f (Get-Date).ToLongTimeString(), $vmContext.Subscription.Name, $vmContext.Subscription.Id,$vmDeployment)
                    }

                    Write-Host ("INFO:    {0} - VM Deployment: {1} | Found {2} VM Names from previous deployment" -f (Get-Date).ToLongTimeString(), $vmDeployment, $vmRgCollection[$vmDeployment].sessionHostNames.Count)
                    Write-Host ("INFO:    {0} - VM Deployment: {1} | Validating VMs in {1}" -f (Get-Date).ToLongTimeString(),$vmDeployment)

                    # Loop to validate VMs via PowerShell, regardless of the return count, the names from the previous deployment output will be used
                    # Loops 3 times at 90 second intervals
                    $i = 0
                    Do {
                        Start-Sleep -Seconds 30
                        $vmStatus = $null
                        $vmStatus = Get-AzVm -ResourceGroupName $vmDeployment
                        If ($vmRgCollection[$vmDeployment].sessionHostNames.Count -eq $vmStatus.Count) { Break }
                        Else { $i++ }
                    } Until ($i -ge 3)

                    Write-Host ("INFO:    {0} - VM Deployment: {1} | VM(s) found: {2}/{3}" -f (Get-Date).ToLongTimeString(),$vmDeployment, $vmStatus.Count, $vmRgCollection[$vmDeployment].sessionHostNames.Count)
                    Write-Host ("INFO:    {0} - VM Deployment: {1} | Starting AVD Extension Deployment..." -f (Get-Date).ToLongTimeString(),$vmDeployment)

                    $templateParams = [Ordered]@{
                        avd_BuildType                   = $vmRgCollection[$vmDeployment].avdBuildType
                        avd_ConfigurationZipUri         = "https://raw.githubusercontent.com/Azure/RDS-Templates/master/ARM-wvd-templates/DSC/Configuration.zip"
                        avd_DeploymentGuid              = $correlationId
                        avd_Dsc1VAZip                   = $avdBlobURLs.Avd1vaPackages
                        avd_DscADMZip                   = $avdBlobURLs.AvdAdmPackages
                        avd_DscBaselineZip              = $avdBlobURLs.AvdBaselinePackages
                        avd_DscCanaryZip                = $avdBlobURLs.AvdCanaryPackages
                        avd_DscFsLogixVhdLocation       = $vmRgCollection[$vmDeployment].dscFsLogixVhdLocation
                        avd_DscHostPoolName             = $vmRgCollection[$vmDeployment].HostPoolName
                        avd_DscHostPoolToken            = $vmRgCollection[$vmDeployment].HostPoolToken
                        avd_DscLocalAdminGroups         = $vmRgCollection[$vmDeployment].dscLocalAdminGroups.Replace("'","").Split(",")
                        avd_LogAnalyticsWorkspaceId     = $avdLaWorkspaceId
                        avd_LogAnalyticsWorkspaceKey    = $avdLaWorkspaceKey
                        avd_Workload                    = ($vmRgCollection[$vmDeployment].HostPoolName.Split("-")[3]).ToUpper()
                        az_Cloud                        = $vmRgCollection[$vmDeployment].azCloud
                        az_Environment                  = ($vmRgCollection[$vmDeployment].HostPoolName.Split("-")[1]).ToUpper()
                        az_LogAnalyticsWorkspaceId      = $vmRgCollection[$vmDeployment].azLogAnalyticsWorkspaceId
                        az_LogAnalyticsResourceId       = $vmRgCollection[$vmDeployment].azLogAnalyticsResourceId
                        az_VirtualMachineNames          = $vmRgCollection[$vmDeployment].SessionHostNames
                        az_VirtualMachineType           = $vmRgCollection[$vmDeployment].azVirtualMachineType
                        dsc_Configuration               = $vmRgCollection[$vmDeployment].dscConfiguration
                        dsc_ConfigurationScript         = $vmRgCollection[$vmDeployment].dscConfigurationScript
                        dsc_ConfigurationZipUri         = $avdBlobURLs.DscConfigurationZip
                        vm_AdminAccountName             = $avdAdminAccount
                        vm_AdminAccountPassword         = $avdAdminPassword
                        vm_DomainFQDN                   = $vmRgCollection[$vmDeployment].vmDomainFQDN
                    }
                    
                    # $DebugPreference = "inquire"
                    # Write-Debug ("Start Extension Deployment: {0}" -f $vmDeployment)
                    # $DebugPreference = "silentlycontinue"
                    try {
                        New-AzResourceGroupDeployment `
                            -Name ("ACS-Extension-Deployment-{0}" -f $correlationId.Split("-")[-1]) `
                            -ResourceGroupName $vmDeployment `
                            -TemplateUri $avdExtensionTemplateUri `
                            -TemplateParameterObject $templateParams `
                            -AsJob | Out-Null

                        While ($true) {
                            $jobInfo = Get-AzResourceGroupDeployment -ResourceGroupName $vmDeployment -Name ("ACS-Extension-Deployment-{0}" -f $correlationId.Split("-")[-1]) -ErrorAction SilentlyContinue
                            If ($jobInfo) {
                                #Get-Job | Remove-Job -Force
                                Write-Verbose ("{0} - Deployment Job Submitted: ACS-Extension-Deployment-{1}" -f (Get-Date).ToLongTimeString(),$correlationId.Split("-")[-1])
                                Break
                            }
                            ElseIf (@(Get-Job -State Failed)) {
                                Write-Warning ("Deployment Job Failed: ACS-Extension-Deployment-{0}" -f $correlationId.Split("-")[-1])
                                #Get-Job | Receive-Job -AutoRemoveJob -Wait
                                Break
                            }
                            Else {
                                Write-Verbose ("{0} - Waiting for job: ACS-Extension-Deployment-{1}" -f (Get-Date).ToLongTimeString(),$correlationId.Split("-")[-1])
                                Start-Sleep -Seconds 5
                            }
                        }
                    }
                    catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
                    [Void]$deploymentJobs.Add($jobInfo)
                }
            }
            Else {
                Write-Warning ("User Cancelled the deployment operation!")
                Return
            }
        }
        Else {
            Write-Host ("INFO:    {0} - ACS Unified Deployment did not succeed - State: {1}" -f (Get-Date).ToLongTimeString(),$Results.ProvisioningState)
        }
    }
    END {
        # $DebugPreference = "inquire"
        # Write-Debug ("End Extension Deployment(s)")
        # $DebugPreference = "silentlycontinue"
        If ($deploymentJobs.Count -gt 0) {
            Write-Host ("`n`rINFO:    {0} - ACS Extension Deployment(s) Created!" -f (Get-Date).ToLongTimeString())
            Foreach ($Job in $deploymentJobs) { Write-Host ("`t VM Resource Group: {0}  |  Deployment: {1}  |  Status: {2}" -f $Job.ResourceGroupName,$Job.DeploymentName,$Job.ProvisioningState) }
        }
    }
}