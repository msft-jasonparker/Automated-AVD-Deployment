[CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
Param (
    [Parameter(Mandatory=$true)]
    [String]$SubscriptionName,

    [Parameter(Mandatory=$true)]
    [String]$Location,

    [Parameter(Mandatory=$true)]
    [String]$DscConfiguration,

    [Parameter(Mandatory=$true)]
    [String]$FsLogixVhdLocation
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

    Function Show-Menu {
        Param(
            [string]$Menu,
            [string]$Title = $(Throw [System.Management.Automation.PSArgumentNullException]::new("Title")),
            [switch]$ClearScreen,
            [Switch]$DisplayOnly,
            [ValidateSet("Full","Mini","Info")]
            $Style = "Full",
            [ValidateSet("White","Cyan","Magenta","Yellow","Green","Red","Gray","DarkGray")]
            $Color = "Gray"
        )
        if ($ClearScreen) {[System.Console]::Clear()}
    
        If ($Style -eq "Full") {
            #build the menu prompt
            $menuPrompt = "`n`r"
            $menuPrompt = "/" * (95)
            $menuPrompt += "`n`r////`n`r//// $Title`n`r////`n`r"
            $menuPrompt += "/" * (95)
            $menuPrompt += "`n`n"
        }
        ElseIf ($Style -eq "Mini") {
            $menuPrompt = "`n`r"
            $menuPrompt = "\" * (80)
            $menuPrompt += "`n$Title`n"
            $menuPrompt += "\" * (80)
            $menuPrompt += "`n"
        }
        ElseIf ($Style -eq "Info") {
            $menuPrompt = "`n`r"
            $menuPrompt = "-" * (80)
            $menuPrompt += "`n-- $Title`n"
            $menuPrompt += "-" * (80)
        }
    
        #add the menu
        $menuPrompt+=$menu
    
        [System.Console]::ForegroundColor = $Color
        If ($DisplayOnly) {Write-Host $menuPrompt}
        Else {Read-Host -Prompt $menuprompt}
        [system.console]::ResetColor()
    }

    Function Get-ChoicePrompt {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $true)]
            [String[]]$OptionList, 
            [Parameter(Mandatory = $false)]
            [String]$Title, 
            [Parameter(Mandatory = $False)]
            [String]$Message = $null, 
            [int]$Default = 0 
        )
        $Options = New-Object System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription] 
        $OptionList | ForEach-Object { $Options.Add((New-Object "System.Management.Automation.Host.ChoiceDescription" -ArgumentList $_)) } 
        $Host.ui.PromptForChoice($Title, $Message, $Options, $Default) 
    }

    # Static Variables
    $StgAcctRgName  ="WVD-CORE-MAP-EASTUS-SVCS-RG"
    $StgAcctSubscription = "WVD-Public-Core"
    $StgAcctName = "vac30artifactblobstore"

    $expirationTime = (Get-Date).AddHours(12)
    $coreAzContext = Set-AzContext -Subscription $StgAcctSubscription
    $stgAccountContext = (Get-AzStorageAccount -Name $StgAcctName -ResourceGroupName $StgAcctRgName -DefaultProfile $coreAzContext).Context
    $dscZipUri = New-AzStorageBlobSASToken -Container dsc -Blob ("{0}.zip" -f $DscConfiguration) -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri

}
PROCESS {
    
    Set-AzContext -Subscription $SubscriptionName | Out-Null
    [System.Collections.ArrayList]$deploymentJobs = @()
    
    Do {
        Write-Verbose "Getting WVD Resource Groups..."
        $RGs = Get-AzResourceGroup -Location $Location -Verbose:$false -Debug:$false | % {$_.ResourceGroupName} | Sort-Object
        Write-Verbose ("Found {0} Azure WVD Resource Groups" -f $RGs.Count)
        $RGSelection = (@"
`n
"@)
        $RGRange = 0..($RGs.Count - 1)
        For ($i = 0; $i -lt $RGs.Count;$i++) {$RGSelection += " [$i] $($RGs[$i])`n"}
        $RGSelection += "`n Please select a Resource Group"

        Do {$RGChoice = Show-Menu -Title "Select an Azure WVD Resource Group" -Menu $RGSelection -Style Full -Color White -ClearScreen}
        While (($RGRange -notcontains $RGChoice) -OR (-NOT $RGChoice.GetType().Name -eq "Int32"))
        
        Clear-Host
        Write-Host ("Selected WVD Resource Group: {0}" -f $RGs[$RGChoice])
        
        $HostPool = Get-AzWvdHostPool -ResourceGroupName $RGs[$RGChoice]
        If ($HostPool) {
            Write-Host ("Host Pool: {0}" -f $HostPool.Name)
            Write-Host ("Host Pool: {0} | Generating Host Pool registration token..." -f $HostPool.Name)
            $wvdHostPoolToken = New-AzWvdRegistrationInfo -ResourceGroupName $RGs[$RGChoice] -HostPoolName $HostPool.Name -ExpirationTime $expirationTime
            $vmNames = Get-AzVm -ResourceGroupName $RGs[$RGChoice] | ForEach-Object {$_.Name}

            Write-Host ("Host Pool: {0} | Starting WVD Session Host Configuration (AsJob)..." -f $HostPool.Name)
            $templateParams = @{
                Name = ("Deploy-WVD-DscConfiguration")
                az_virtualMachineNames = $vmNames
                wvd_dscConfigurationScript = $DscConfiguration
                wvd_deploymentType = $HostPool.Tag["WVD-Deployment"].Split("-")[0]
                wvd_deploymentPurpose = $HostPool.Tag["WVD-Deployment"].Split("-")[1]
                wvd_fsLogixVHDLocation = $FsLogixVhdLocation
                wvd_hostPoolName = $HostPool.Name
                wvd_hostPoolToken = $wvdHostPoolToken.Token
                wvd_sessionHostDSCModuleZipUri = $dscZipUri
                ResourceGroupName = $RGs[$RGChoice]
            }

            $currentDirectory = Get-Location
            If ($PSCmdlet.ShouldProcess($HostPool.Name,"Initiate DSC Configuration Deployment")) {
                $deploymentJob = New-AzResourceGroupDeployment @templateParams -TemplateFile ("{0}\Deploy-WVD-BaselineConfig.json" -f $currentDirectory.Path) -TemplateParameterFile ("{0}\Deploy-WVD-BaselineConfig.parameters.json" -f $currentDirectory.Path) -AsJob
                [Void]$deploymentJobs.Add($deploymentJob)
                Write-Host ("Active Deployment Jobs: {0}" -f $deploymentJobs.Count)
            }
            Else {Write-Host "Configuration cancelled!"}
        }
        Else { Write-Warning ("No WVD Host Pools found in {0}" -f $RGs[$RGChoice])}
                
        $Done = Get-ChoicePrompt -Title "`n" -Message "Select another WVD Resource Group?" -OptionList "&Yes","&No"
    } Until ($Done -eq 1)

    If ($deploymentJobs.Count -gt 0) {
        Show-Menu -Title "WVD Configuration Deployments" -DisplayOnly -ClearScreen -Color White -Style Info
        _WaitOnJobs -Jobs $deploymentJobs -maxDuration 60
    }
}