Function Register-AzWvdStateConfiguration {
    [CmdletBinding()]
    Param(

    )
    BEGIN {

    }
    PROCESS {
        
    }
}

If ($Results.ProvisioningState -eq "Succeeded" -AND $EnablePostConfiguration) {
    Write-Host ("[{0}] WVD Scale Unit Deployment Succeeded!" -f $Results.Timestamp.ToLocalTime())
    [PSCustomObject]$Output = $Results.Outputs.Item("hostPoolsDeployed").Value.ToString() | ConvertFrom-Json
    $outputHash = $Output | Group-Object hostPoolName -AsHashTable -AsString

    $logEntry = [PSCustomObject]@{
        Timestamp         = [DateTime]::UtcNow.ToString('o')
        CorrelationId     = $correlationId
        Computer          = $env:COMPUTERNAME
        UserName          = $userName
        EntryType         = "INFO"
        Subscription      = $subscriptionName
        ResourceGroupName = $DeploymentResourceGroup
        DeploymentName    = ("Deploy-WVD-ScaleUnit-{0}" -f $deploymentString)
        DeploymentStatus  = $Results.ProvisioningState
        DeploymentType    = "ScaleUnit"
        HostPoolName      = [System.String]::Empty
    }
    New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false

    $wvdDscConfigZipUrl = Get-LatestWVDConfigZip -OutputType Local -LocalPath $deploymentParameters.parameters.wvd_hostPoolConfig.value.configs[0].wvdArtifactLocation -Verbose:$false

    [System.Collections.ArrayList]$deploymentJobs = @()
    Foreach ($hostPool in $outputHash.Keys) {
        #$dscZipUri = New-AzStorageBlobSASToken -Container dsc -Blob $outputHash[$hostPool].dscConfiguration -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        Write-Host ("[{0}] Host Pool: {1} | Generating Host Pool registration token..." -f (Get-Date), $hostPool)
        $wvdHostPoolToken = (Update-AzWvdHostPool -ResourceGroupName $outputHash[$hostPool].resourceGroupName -HostPoolName $HostPool -RegistrationInfoExpirationTime $expirationTime -RegistrationInfoRegistrationTokenOperation Update).RegistrationInfoToken
        $vmNames = Get-AzVm -ResourceGroupName $outputHash[$hostPool].resourceGroupName | ForEach-Object { $_.Name }

        Write-Host ("[{0}] Host Pool: {1} | Starting WVD Session Host Configuration..." -f (Get-Date), $hostPool)

        $logEntry = [PSCustomObject]@{
            Timestamp         = [DateTime]::UtcNow.ToString('o')
            CorrelationId     = $correlationId
            Computer          = $env:COMPUTERNAME
            UserName          = $userName
            EntryType         = "INFO"
            Subscription      = $subscriptionName
            ResourceGroupName = $outputHash[$hostPool].resourceGroupName
            DeploymentName    = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
            DeploymentStatus  = "Starting"
            DeploymentType    = "Configuration"
            HostPoolName      = $hostPool
        }
        New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false

        $templateParams = [Ordered]@{
            Name                           = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
            ResourceGroupName              = $outputHash[$hostPool].resourceGroupName
            TemplateUri                    = $DscTemplateUri
            TemplateParameterFile          = ("{0}\dsc.parameters.json" -f $env:TEMP)
        }
        
        Write-Debug ("Start Configuration: {0}" -f $hostPool)
        $deploymentJob = New-AzResourceGroupDeployment @templateParams -AsJob -ErrorAction Stop
        While ($true) {
            $jobInfo = Get-AzResourceGroupDeployment -ResourceGroupName $outputHash[$hostPool].resourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue
            If ($jobInfo) { Break }
            Else {
                Write-Verbose ("[{0}] Waiting for job: Deploy-WVD-DscConfiguration-{1}" -f (Get-Date), $deploymentString)
                Start-Sleep -Seconds 5
            }
        }

        $logEntry = [PSCustomObject]@{
            Timestamp         = [DateTime]::UtcNow.ToString('o')
            CorrelationId     = $correlationId
            Computer          = $env:COMPUTERNAME
            UserName          = $userName
            EntryType         = "INFO"
            Subscription      = $subscriptionName
            ResourceGroupName = $outputHash[$hostPool].resourceGroupName
            DeploymentName    = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
            DeploymentStatus  = $jobInfo.ProvisioningState
            DeploymentType    = "Configuration"
            HostPoolName      = $hostPool
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
                If ($deploymentResults.ProvisioningState -eq "Running") { $i++ }
                $elapsedTime = $deploymentResults.TimeStamp.ToUniversalTime() - $currentTime.ToUniversalTime()
                $obj = [PSCustomObject][Ordered]@{
                    Name          = ("Deploy-WVD-DscConfiguration-{0}  " -f $deploymentString)
                    ResourceGroup = ("{0}  " -f $outputHash[$hostPool].resourceGroupName)
                    Status        = ("{0}  " -f $deploymentResults.ProvisioningState)
                    Duration      = ("{0:N0}.{1:N0}:{2:N0}:{3:N0}" -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds)
                }
                $Jobs.Add($obj)
            }
            Else {
                $i++
                $obj = [PSCustomObject][Ordered]@{
                    Name          = ("Deploy-WVD-DscConfiguration-{0}  " -f $deploymentString)
                    ResourceGroup = ("{0}  " -f $outputHash[$hostPool].resourceGroupName)
                    Status        = ("Not Found  ")
                    Duration      = ("N/A")
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
            Timestamp         = [DateTime]::UtcNow.ToString('o')
            CorrelationId     = $correlationId
            Computer          = $env:COMPUTERNAME
            UserName          = $userName
            EntryType         = $type
            Subscription      = $subscriptionName
            ResourceGroupName = $outputHash[$hostPool].resourceGroupName
            DeploymentName    = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
            DeploymentStatus  = $job.ProvisioningState
            DeploymentType    = "Configuration"
            HostPoolName      = $hostPool
        }
        New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
        If ($SelfHosted) { Disable-AzWvdMaintanence -ResourceGroupName $outputHash[$hostPool].resourceGroupName -HostPoolName $hostPool -SessionHostGroup ALL -LogAnalyticsResourceGroup $DeploymentResourceGroup -LogAnalyticsWorkspace $LogAnalyticsWorkspace -CorrelationId $correlationId -SelfHosted }
        Else { Disable-AzWvdMaintanence -ResourceGroupName $outputHash[$hostPool].resourceGroupName -HostPoolName $hostPool -SessionHostGroup ALL -LogAnalyticsResourceGroup $DeploymentResourceGroup -LogAnalyticsWorkspace $LogAnalyticsWorkspace -CorrelationId $correlationId }
    }

}