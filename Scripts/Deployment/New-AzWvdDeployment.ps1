[CmdletBinding()]
Param(
    $WvdSubscription,
    $StgAcctRgName,
    $StgAcctName
)

BEGIN {
    Function _WaitOnJobs {
        <#
            .SYNOPSIS
                Waits upto 60 minutes for background jobs to finish, otherwise, stops the jobs
            .DESCRIPTION
                If a background job is running for longer than the $maxDuration, the job will be stopped to prevent endless jobs.
        #>
        [CmdletBinding()]
        Param (
            [System.Collections.ArrayList]$Jobs = @(),
            [System.Int32]$maxDuration = 60
        )
    
        $timeSpan = [timespan]::FromMinutes($maxDuration)
        Write-Host ("Waiting on Jobs") -NoNewline
        While (($Jobs | Where-Object {$_.State -eq "Running"}).Count -gt 0) {
            $utcNow = [DateTime]::UtcNow
            Foreach ($Job in ($Jobs | Where-Object {$_.State -eq "Running"})) {
                If ($utcNow.Subtract($Job.PSBeginTime.ToUniversalTime()) -gt $timeSpan) {
                    $Job | Stop-Job -Confirm:$false
                }
            }
            Write-Host (".") -NoNewline
            Start-Sleep -Milliseconds 2500
        }
        Write-Host ("Done!")
    }

    #Install-Module Az.DesktopVirtualization -Force
    Import-Module Az.DesktopVirtualization -Force
}
PROCESS {
    Write-Host ("[{0}] Setting up inital variables..." -f (Get-Date))
    $expirationTime = (Get-Date).AddHours(24)

    Write-Host ("[{0}] Connecting to Azure Cloud..." -f (Get-Date))
    Add-AzAccount -Identity -Subscription "WVD-Public-Core" | Out-Null
    $coreContext = Get-AzContext
    $subscriptionName = $coreContext.Name.Split("(")[0].Trim(" ")
    $account = $coreContext.Account.Id
    Write-Host ("`tConnected to: {0}, using {1}" -f $subscriptionName,$account)

    Write-Host ("[{0}] Generating Storage SAS Tokens and fetching various URL(s)..." -f (Get-Date))  
    
    If (Get-AzStorageAccount -Name $StgAcctName -ResourceGroupName $StgAcctRgName) {
        $stgAccountContext = (Get-AzStorageAccount -Name $StgAcctName -ResourceGroupName $StgAcctRgName -DefaultProfile $coreContext).Context
    }
    Else { Throw "Unable to locate Storage Account" }
    $wvdHostPoolTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "WindowsVirtualDesktop/Deploy-WVD-HostPool.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
    $wvdSessionHostTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "WindowsVirtualDesktop/Deploy-WVD-SessionHosts.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
    
    $wvdContext = Set-AzContext -Subscription $WvdSubscription
    $subscriptionName = $wvdContext.Name.Split("(")[0].Trim(" ")
    $account = $wvdContext.Account.Id
    Write-Host ("`tConnected to: {0}, using {1}" -f $subscriptionName,$account)

    Write-Host ("[{0}] Starting WVD Scale Unit Deployment..." -f (Get-Date))
    $deploymentString = ([Guid]::NewGuid()).Guid.Split("-")[-1]
    $Results = New-AzResourceGroupDeployment `
        -Name ("Deploy-WVD-ScaleUnit-{0}" -f $deploymentString) `
        -ResourceGroupName "WVD-PROD-MAP-EASTUS-SVCS-RG" `
        -wvd_hostPoolTemplateUri $wvdHostPoolTemplateUri `
        -wvd_sessionHostTemplateUri $wvdSessionHostTemplateUri `
        -wvd_deploymentString $deploymentString `
        -TemplateFile ".\Deployment\Deploy-WVD-ScaleUnit.json" `
        -TemplateParameterFile ".\Deployment\Deploy-WVD-ScaleUnit.parameters.json"

    If ($Results.ProvisioningState -eq "Succeeded") {
        Write-Host ("[{0}] WVD Scale Unit Deployment Succeeded!" -f $Results.Timestamp.ToLocalTime())
        [PSCustomObject]$Output = $Results.Outputs.Item("hostPoolsDeployed").Value.ToString() | ConvertFrom-Json
        $outputHash = $Output | Group-Object hostPoolName -AsHashTable -AsString

        [System.Collections.ArrayList]$deploymentJobs = @()
        Foreach ($hostPool in $outputHash.Keys) {

            $dscZipUri = New-AzStorageBlobSASToken -Container dsc -Blob $outputHash[$hostPool].dscConfiguration -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri

            Write-Host ("[{0}] Host Pool: {1} | Generating Host Pool registration token..." -f (Get-Date), $hostPool)
            $wvdHostPoolToken = New-AzWvdRegistrationInfo -ResourceGroupName $outputHash[$hostPool].resourceGroupName -HostPoolName $hostPool -ExpirationTime $expirationTime
            $vmNames = Get-AzVm -ResourceGroupName $outputHash[$hostPool].resourceGroupName | ForEach-Object {$_.Name}

            Write-Host ("[{0}] Host Pool: {1} | Starting WVD Session Host Configuration..." -f (Get-Date), $hostPool)
            $templateParams = @{
                Name = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                az_virtualMachineNames = $vmNames
                wvd_dscConfigurationScript = $outputHash[$hostPool].dscConfiguration.Trim(".zip")
                wvd_deploymentType = $outputHash[$hostPool].deploymentType
                wvd_deploymentPurpose = $outputHash[$hostPool].deploymentPurpose
                wvd_fsLogixVHDLocation = $outputHash[$hostPool].fsLogixVhdLocation
                wvd_hostPoolName = $hostPool
                wvd_hostPoolToken = $wvdHostPoolToken.Token
                wvd_sessionHostDSCModuleZipUri = $dscZipUri
                ResourceGroupName = $outputHash[$hostPool].resourceGroupName
            }
            
            $deploymentJob = New-AzResourceGroupDeployment @templateParams -TemplateFile ".\Deployment\LinkedTemplates\Deploy-WVD-BaselineConfig.json" -TemplateParameterFile ".\Deployment\LinkedTemplates\Deploy-WVD-BaselineConfig.parameters.json" -AsJob
            [Void]$deploymentJobs.Add($deploymentJob)
        }

        _WaitOnJobs -Jobs $deploymentJobs -maxDuration 60
        #While ((Get-Job -State Running).Count -gt 0) { Start-Sleep -Milliseconds 2500 }
        
        Get-Job | Group-Object State -NoElement
    }
    Else { Write-Host ("[{0}] WVD Scale Unit Deployment did not succeed - State: {1}" -f (Get-Date),$Results.ProvisioningState)}
}