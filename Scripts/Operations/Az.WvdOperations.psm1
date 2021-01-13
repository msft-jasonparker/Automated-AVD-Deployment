Function Set-FunctionBreakPoint {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Enable","Disable")]
        [System.String]$State,

        [Parmeter(Mandatory=$true)]
        [System.String]$Message
    )
    Switch ($State) {
        "Enable" { $DebugPreference = "Inquire" }
        "Disable" { $DebugPreference = "SilentlyContinue" }
    }
    Write-Debug $Message
}

Function Create-AccessToken {
    param($resourceURI)

    If ($null -eq $env:MSI_ENDPOINT) {
        $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
        if(!$azProfile.Accounts.Count) { Write-Error "Ensure you have logged in before calling this function." }
        $azContext = Get-AzContext
        $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azProfile)
        $token = $profileClient.AcquireAccessToken($azContext.Tenant.TenantId)
        Return $token.AccessToken
    }
    Else {
        $tokenAuthURI = $env:MSI_ENDPOINT + "?resource=$resourceURI&api-version=2017-09-01"
        $headers =  @{'Secret'="$env:MSI_SECRET"}
        try {
            $tokenResponse = Invoke-RestMethod -Method Get -header $headers -Uri $tokenAuthURI -ErrorAction:stop
            return $tokenResponse.access_token
        }
        catch {
            write-error "Unable to retrieve access token $error"
            exit 1
        }
    }
}

Function Push-DscConfigToAzStorage {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        $StorageAccountResourceGroup,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Storage/storageAccounts","StorageAccountResourceGroup")]
        $StorageAccountName,

        [Parameter(Mandatory=$true)]
        [System.String]$Container
    )
    BEGIN {}
    PROCESS {
        Show-Menu -Title "Select Desired State Configuration .PS1 File(s)" -Style Mini -Color Yellow -DisplayOnly
        $Files = Get-FileNameDialog -InitialDirectory [System.IO.Path]::GetFullPath($PWD)
        Write-Verbose ("Found {0} Files" -f $Files.Count)
        Foreach ($File in $Files) { Publish-AzVMDscConfiguration -ResourceGroupName $StorageAccountResourceGroup -StorageAccountName $StorageAccountName -ContainerName $Container -ConfigurationPath $File -Force -Verbose:$false }
    }
}

Function New-AzWvdLogEntry {
    <#
        .SYNOPSIS
            Writes a log entry into an Azure Log Analytics workspace in a Custom Log table.
        .DESCRIPTION
            After creating a log entry using the  _NewComplianceLogEntry function, this function will inject the log entry into an Azure Log Analytics workspace. Provide the workspace id, shared key, custom table name, and the $logentry variable. If the custom log exists, it adds the data to the table, otherwise it will create the table.
    #>
    [CmdletBinding()]
    Param (
        $customerId,
        $sharedKey,
        $logName,
        $logMessage,
        [Switch]$PassThru
    )

    BEGIN {
        Function _GetLAAuthorization {
            [CmdletBinding()]
            Param(
                $customerId,
                $sharedKey,
                $date,
                $contentLength,
                $method,
                $contentType,
                $resource
            )
            $xHeaders = "x-ms-date:" + $date
            $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
            $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
            $keyBytes = [Convert]::FromBase64String($sharedKey)
            $sha256 = New-Object System.Security.Cryptography.HMACSHA256
            $sha256.Key = $keyBytes
            $calculatedHash = $sha256.ComputeHash($bytesToHash)
            $encodedHash = [Convert]::ToBase64String($calculatedHash)
            $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
            return $authorization
        }
    }
    PROCESS {
        If ($PassThru) {
            If ($logMessage.Count -gt 1) { $logMessage | ForEach-Object { Write-Host $_ -ForegroundColor Yellow } }
            Else { Write-Host $logMessage -ForegroundColor Yellow }
        }
        Else {
            $logJSON = $logMessage | ConvertTo-Json
            $body = ([System.Text.Encoding]::UTF8.GetBytes($logJSON))
            $method = "POST"
            $contentType = "application/json"
            $resource = "/api/logs"
            $rfc1123date = [DateTime]::UtcNow.ToString("r")
            $contentLength = $body.Length
            $signature = _GetLAAuthorization -customerId $customerId -sharedKey $sharedKey -date $rfc1123date -contentLength $contentLength -method $method -contentType $contentType -resource $resource 
            $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
            $OMSheaders = @{
                "Authorization"        = $signature;
                "Log-Type"             = $logName;
                "x-ms-date"            = $rfc1123date;
                "time-generated-field" = "Timestamp";
            }
    
            try {
                Invoke-WebRequest -Uri $uri -Method POST -ContentType $contentType -Headers $OMSheaders -Body $body -UseBasicParsing | Out-Null
            }
            catch {
                Write-Warning $_.Exception.Message
            }
        }
    }
}

Function _WaitOnJobs {
    <#
        .SYNOPSIS
            Waits upto 60 minutes for background jobs to finish, otherwise, stops the jobs
        .DESCRIPTION
            Creates a while loop for running jobs. If a background job is running for longer than the -maxDuration, the job will be stopped to prevent an endless job loop.
    #>
    [CmdletBinding()]
    Param (
        # Array of current jobs
        [System.Collections.ArrayList]$Jobs = @(Get-Job),

        # Maximum number of minutes to allow the the jobs to run to completion
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

Function Get-FileNameDialog {
    Param ($InitialDirectory)
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null 
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    If ($InitialDirectory) { $OpenFileDialog.initialDirectory = $InitialDirectory }
    Else { $OpenFileDialog.InitialDirectory = [system.io.path]::GetDirectoryName($MyInvocation.PSScriptRoot) }
    $OpenFileDialog.Multiselect = $true
    $OpenFileDialog.filter = "All files (*.*)| *.*"
    $OpenFileDialog.ShowDialog() | Out-Null
    If ($OpenFileDialog.FileNames) { Return $OpenFileDialog.FileNames }
    Else { Return $OpenFileDialog.filename }
}

Function Show-Menu {
    <#
        .SYNOPSIS
            Shows a console based menu and title or just a console title banner in a variety of colors and stles.
        .DESCRIPTION
            Create a console based menu and use this function to display it with a descriptive title bar. This function is primarily used to display the title bar in a variety of colors and sytles. It is useful when used to convey important information to the console operator.
    #>
    Param (
        # Single line title or banner used as a desciption or message to the console operator
        [Parameter(Position=0,Mandatory=$true)]
        [System.String]$Title,

        # Console based menu with multiple selection options
        [Parameter(Position=1,Mandatory=$false)]
        [System.String]$Menu,

        # Allows for a variety of style selections and sizes, default style (full)
        [Parameter(Position=2,Mandatory=$false)]
        [ValidateSet("Full","Mini","Info")]
        [System.String]$Style = "Full",

        # Foreground text colors
        [Parameter(Position=3,Mandatory=$false)]
        [ValidateSet("White","Cyan","DarkCyan","Magenta","Yellow","DarkYellow","Green","DarkGreen","Red","DarkRed","Gray","DarkGray","Blue","DarkBlue")]
        [System.String]$Color = "Gray",

        # Clears the console screen before displaying the menu / title
        [Parameter(Position=4,Mandatory=$false)]
        [Switch]$ClearScreen,

        # Does not prompt for menu selection, shows the menu display only.
        [Parameter(Position=5,Mandatory=$false)]
        [Switch]$DisplayOnly
    )

    [System.Text.StringBuilder]$menuPrompt = ""
    Switch($Style) {
        "Full" {
            [Void]$menuPrompt.AppendLine("/" * (95))
            [Void]$menuPrompt.AppendLine("////`n`r//// $Title`n`r////")
            [Void]$menuPrompt.AppendLine("/" * (95))
        }
        "Mini" {
            [Void]$menuPrompt.AppendLine("\" * (80))
            [Void]$menuPrompt.AppendLine(" $Title")
            [Void]$menuPrompt.AppendLine("\" * (80))
        }
        "Info" {
            [Void]$menuPrompt.AppendLine("-" * (80))
            [Void]$menuPrompt.AppendLine("-- $Title")
            [Void]$menuPrompt.AppendLine("-" * (80))
        }
    }

    #add the menu
    If (-NOT [System.String]::IsNullOrEmpty($Menu)) { [Void]$menuPrompt.Append($Menu) }
    If ($ClearScreen) { [System.Console]::Clear() }
    If ($DisplayOnly) {Write-Host $menuPrompt.ToString() -ForegroundColor $Color}
    Else {
        [System.Console]::ForegroundColor = $Color
        Read-Host -Prompt $menuPrompt.ToString()
        [System.Console]::ResetColor()
    }    
}

Function Get-ChoicePrompt {
    <#
        .SYNOPSIS
            Creates a customizable user prompt at the console.
        .DESCRIPTION
            This function will create a custom prompt with custom selections for the operator to make specific decisions or choices
    #>
    [CmdletBinding()]
    Param (
        # Array of strings for the options to be presented ("Yes","No" -or- "&Yes",&No"), use the '&' symbol as the designated letter for selection
        [Parameter(Mandatory = $true)]
        [String[]]$OptionList,

        # Title of the choice prompt
        [Parameter(Mandatory = $false)]
        [String]$Title,

        # Message to convey to the user / operator
        [Parameter(Mandatory = $False)]
        [String]$Message = $null,

        # Select the default choice (index based on the number of options)
        [int]$Default = 0 
    )
    $Options = New-Object System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription] 
    $OptionList | ForEach-Object { $Options.Add((New-Object "System.Management.Automation.Host.ChoiceDescription" -ArgumentList $_)) } 
    $Host.ui.PromptForChoice($Title, $Message, $Options, $Default) 
}

Function Get-LatestWVDConfigZip {
    <#
        .SYNOPSIS
            Fetches the latest WVD Configuration zip file for WVD Deployments
        .DESCRIPTION
            This function takes no parameters and simply fetches the latest configuration zip file for WVD Deployments from the Microsoft WVD Product Group
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [System.String]$LocalPath,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Local","Remote")]
        [System.String]$OutputType
    )
    try {
        If ($OutputType -eq "Local" -and [System.String]::IsNullOrEmpty($LocalPath)) {
            Write-Warning ("OutputType is 'Local', but LocalPath is empty, defaulting to 'Remote' OutputType")
            $OutputType = "Remote"
        }
        ElseIf ($OutputType -eq "Remote" -and (![System.String]::IsNullOrEmpty($LocalPath))) { Write-Warning ("OutputType is 'Remote' and LocalPath is defined, ignoring LocalPath") }
        Else { Write-Verbose ("WVD Configuration output type: {0}" -f $OutputType) }

        [xml]$results = (Invoke-WebRequest -Uri "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts?restype=container&comp=list" -UseBasicParsing -ErrorAction SilentlyContinue).Content.Substring(3)
        If ($results.EnumerationResults.Blobs.Blob.Count -gt 0) {
            Write-Verbose ("Found {0} Blobs for WVD Configuration" -f $results.EnumerationResults.Blobs.Blob.Count)
            [System.Collections.ArrayList]$list = @()
            $x = $results.EnumerationResults.Blobs.Blob | Where-Object {$_.Name -like "Configuration_*"}
            $x | ForEach-Object {
                $dateindex = $_.Name.IndexOf("_")
                $config = $_ | Select-Object Url,@{l='Date';e={$_.Name.Substring($dateindex + 1).Split(".")[0] | Get-Date}}
                [void]$list.Add($config)
            }

            If ($OutputType -eq "Remote") { Return ($list | Sort-Object Date -Descending | Select-Object -First 1).Url }
            Else {
                If (Test-Path -Path $LocalPath) {
                    $latestZipUri = ($list | Sort-Object Date -Descending | Select-Object -First 1).Url
                    (New-Object System.Net.WebClient).DownloadFile($latestZipUri,("{0}\wvdConfiguration.zip" -f $LocalPath))
                    $wvdConfigurationZip = Get-ChildItem -Path ("{0}\wvdConfiguration.zip" -f $LocalPath) -File
                    If ($wvdConfigurationZip) { Return $wvdConfigurationZip.FullName }
                }
                Else {
                    Write-Warning ("The LocalPath defined does not exist ({0})" -f $LocalPath)
                    Write-Verbose ("Invalid LocalPath, using remote path!")
                    Return ($list | Sort-Object Date -Descending | Select-Object -First 1).Url
                }
            }
        }
        Else {
            If ($OutputType -eq "Remote") { Return "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration.zip" }
            Else {
                If (Test-Path -Path ("{0}\wvdConfiguration.zip" -f $LocalPath)) {
                    $wvdConfigurationZip = Get-ChildItem -Path ("{0}\wvdConfiguration.zip" -f $LocalPath) -File
                    If ($wvdConfigurationZip) { Return $wvdConfigurationZip.FullName }
                }
                Else {
                    Write-Warning ("The LocalPath defined does not exist ({0})" -f $LocalPath)
                    Write-Verbose ("Invalid LocalPath, using remote path!")
                    Return "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration.zip"
                }
            }
        }
    }
    catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
}

Function Enable-AzWvdMaintanence {
    <#
        .SYNOPSIS
            Puts a specific group of session hosts in a host pool into 'maintenance'
        .DESCRIPTION
            This function targets a specific host pool and group of session hosts, changes their Azure maintenance tag to TRUE and turns on drain mode to prevent new connections. Use of this function is for session host redeployment for monthly patching or session host recycling.
    #>
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
    Param (
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
        [System.String]$SessionHostGroup,

        [Parameter(Mandatory=$false)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$LogAnalyticsResourceGroup,

        [Parameter(Mandatory=$false)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.OperationalInsights/workspaces","DeploymentResourceGroup")]
        [System.String]$LogAnalyticsWorkspace,

        [Parameter(ParameterSetName="SelfHosted")]
        [System.Guid]$CorrelationId,

        [Parameter(ParameterSetName="SelfHosted")]
        [Switch]$SelfHosted
    )
    BEGIN {
        #Requires -Modules @{ ModuleName = "Az.DesktopVirtualization"; ModuleVersion = "2.0.0" }
        
        $azContext = Get-AzContext
        $userName = ("{0} ({1})" -f $azContext.Account.Id,$azContext.Account.Type)
        If ($SelfHosted) {
            $ConfirmPreference = "None"
            $ProgressPreference = "SilentlyContinue"
            $VerbosePreference = "Continue"
            If (!$CorrelationId) {
                Write-Warning ("MISSING CORRELATIONID, LOGGING WILL BE COMPROMISED, CREATING NEW ID!")
                $CorrelationId = [System.Guid]::NewGuid()
            }
            If ($env:COMPUTERNAME -ne "GITHUBRUNNER" -AND $azContext.Account.Type -ne "ManagedService") {
                Write-Warning ("NOT EXECUTED FROM GITHUB ACTION RUNNER, ABORTING THE OPERATION!")
                Exit
            }
        }
        Else {
            If ($env:COMPUTERNAME -eq "GITHUBRUNNER" -AND $azContext.Account.Type -eq "ManagedService") {
                Write-Warning ("EXECUTED FROM GITHUB ACTION RUNNER, ENABLING SELFHOSTED SWITCH!")
                $SelfHosted = $true
                $ConfirmPreference = "None"
                $ProgressPreference = "SilentlyContinue"
                $VerbosePreference = "Continue"
            }
            If (!$CorrelationId) {
                Write-Warning ("MISSING CORRELATIONID, LOGGING WILL BE COMPROMISED, CREATING NEW ID!")
                $CorrelationId = [System.Guid]::NewGuid()
            }
        }
    }
    PROCESS {
        try {
            # variables for writing data to log analytics
            $azLogAnalyticsId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspace).CustomerId.ToString()
            $azLogAnalyticsKey = (Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspace).PrimarySharedKey
            
            # logoff message sent to users with active sessions
            $Global:LogOffMessage = (@"
{0}
{1}
{1}  This virtual desktop is being prepared for maintenance.
{1}  If you would like to continue working, please LOGOFF and
{1}  then SIGN-IN again. Do NOT close the window / session
{1}  or simply disconnect.
{1}  
{1}  SHUTDOWN IN 5 MINUTES!
{1}
{0}
"@ -f ("/"*80),"//") # characters used to format the message prompt

            # collection the virtual machines based on WVD-Group tag
            Write-Verbose ("[{0}] Gathering Session Hosts from Group {1}" -f $HostPoolName,$SessionHostGroup)
            [System.Collections.Generic.List[System.Object]]$vmCollection = @()
            If ($SessionHostGroup -eq "ALL") { Get-AzVM -ResourceGroupName $ResourceGroupName -Status | ForEach-Object { $vmCollection.Add($_) | Out-Null } }
            Else { Get-AzVM -ResourceGroupName $ResourceGroupName -Status | Where-Object { $_.Tags["WVD-Group"] -eq $SessionHostGroup } | ForEach-Object { $vmCollection.Add($_) | Out-Null } }
            
            # loop through the virtual machines and add the session host information to the vm object
            $i = 0
            $sessionHostCount = 0
            Foreach ($virtualMachine in $vmCollection) {
                Write-Progress -Activity ("[{0}] Gathering Session Hosts from Group {1}" -f $HostPoolName,$SessionHostGroup.ToUpper()) -Status ("Session Hosts Collected: {0}" -f $sessionHostCount) -CurrentOperation $virtualMachine.Name -PercentComplete (($i / $vmCollection.Count) * 100)
                $sessionHost = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName | Where-Object {$_.ResourceId -eq $virtualMachine.Id}
                
                If ($sessionHost) {
                    $sessionHostCount++
                    $virtualMachine | Add-Member -NotePropertyName SessionHost -NotePropertyValue $sessionHost
                }
                Else {
                    Write-Warning ("[{0}] Unable to match Virtual Machine object to Session Host object, removing the VM from processing collection!" -f $virtualMachine.Name)
                    If ($null -eq $missingVMs) {
                        $missingVMs = [System.Collections.Generic.List[System.Object]]@()
                        $missingVMs.Add($virtualMachine)
                    }
                    Else { $missingVMs.Add($virtualMachine) }
                }
                $i++
            }
            Write-Progress -Activity ("[{0}] Gathering Session Hosts from Group {1}" -f $HostPoolName,$SessionHostGroup.ToUpper()) -Completed
            If ($missingVMs.Count -gt 0) { $missingVMs | ForEach-Object {$vmCollection.Remove($_) | Out-Null} }

            Write-Warning ("PLEASE REVIEW THE COMMENT BASED HELP FOR THIS COMMAND - PROCEEDING WILL FORIBLY LOGOFF USERS AFTER A 5 MINUTE GRACE PERIOD!")

            # prevent this prompt by using -Confirm $false
            If ($PSCmdlet.ShouldProcess(("{0} WVD Session Hosts" -f $vmCollection.Count),"ENABLE maintenace and DRAIN current sessions")) {
                # loop through each vm in the collection, update the maintenance/dsc tag and turn off drain mode
                If ($SessionHostGroup -eq "ALL") {
                    Write-Verbose ("Updating 'WVD-Maintenance' Tag on Host Pool {0}" -f $HostPoolName)
                    $HostPool = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName
                    Update-AzTag -ResourceId $HostPool.Id -Tag @{"WVD-Maintenance" = $true} -Operation Merge | Out-Null
                    $logEntry = [PSCustomObject]@{
                        Timestamp = [DateTime]::UtcNow.ToString('o')
                        CorrelationId = $correlationId
                        Computer = $env:COMPUTERNAME
                        UserName = $userName
                        EntryType = "INFO"
                        Subscription = $azContext.Subscription.Name
                        ResourceGroupName = $ResourceGroupName
                        HostPoolName = $HostPoolName
                        SessionHostGroup = $SessionHostGroup.ToUpper()
                        'WVD-Maintenance' = 'True'
                    }
                    New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_Maintenance_CL" -logMessage $logEntry -Verbose:$false
                }
                
                $x = 0
                $msgsSent = 0
                Foreach ($virtualMachine in $vmCollection) {
                    Write-Progress -Id 42 -Activity ("[{0}] Updating Maintenance Tag, Enabling Drain Mode and sending Logoff Message" -f $HostPoolName) -Status ("Session Hosts Updated: {0} | Messages Sent: {1}" -f $x,$msgsSent) -CurrentOperation $virtualMachine.SessionHost.Name -PercentComplete (($x / $vmCollection.Count) * 100)
                    $tagUpdate = @{"WVD-Maintenance" = $true}
                    Update-AzTag -ResourceId $virtualMachine.Id -Tag $tagUpdate -Operation Merge | Out-Null
                    Update-AzWvdSessionHost -Name $virtualMachine.SessionHost.Name.Split("/")[-1] -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -AllowNewSession:$false | Out-Null
                    $userSessions = Get-AzWvdUserSession -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -SessionHostName $virtualMachine.sessionHost.Name.Split("/")[-1]
                    If ($userSessions) {
                        Foreach ($session in $userSessions.Where{$_.SessionState -ne "Disconnected"}) {
                            Write-Progress -ParentId 42 -Activity ("Sending Logoff Messages") -Status ("Sessions: {0}" -f $userSessions.Where{$_.SessionState -ne "Disconnected"}.Count)
                            Send-AzWvdUserSessionMessage `
                                -SessionHostName $virtualMachine.sessionHost.Name.Split("/")[-1] `
                                -ResourceGroupName $ResourceGroupName `
                                -HostPoolName $HostPoolName `
                                -MessageTitle "!! WARNING - SYSTEM MAINTENANCE !!" `
                                -MessageBody $Global:LogOffMessage `
                                -UserSessionId $session.Name.Split("/")[-1]
                            $msgsSent++
                        }
                        Write-Progress -ParentId 42 -Activity ("Sending Logoff Messages") -Completed
                    }
                    $x++
                    $logEntry = [PSCustomObject]@{
                        Timestamp = [DateTime]::UtcNow.ToString('o')
                        CorrelationId = $correlationId
                        Computer = $env:COMPUTERNAME
                        UserName = $userName
                        EntryType = "INFO"
                        Subscription = $azContext.Subscription.Name
                        ResourceGroupName = $ResourceGroupName
                        HostPoolName = $HostPoolName
                        SessionHostGroup = $SessionHostGroup.ToUpper()
                        SessionHostName = $virtualMachine.SessionHost.Name.Split("/")[-1]
                        AllowNewSessions = "False"
                        'WVD-Maintenance' = "True"
                    }
                    New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_Maintenance_CL" -logMessage $logEntry -Verbose:$false
                }
                Write-Progress -Id 42 -Activity ("[{0}] Updating Maintenance Tag and Drain Mode" -f $HostPoolName) -Completed

                # 5 minute sleep timer to allow active users to save work and logoff - update these values to change the duration
                If ($msgsSent -gt 0) {
                    For ($i = 0; $i -lt 300; $i++) {
                        Write-Progress -Activity "WVD Session Logoff Stall Timer" -Status "Please wait..." -SecondsRemaining (300 - $i)
                        Start-Sleep -Milliseconds 999
                    }
                    Write-Progress -Activity "WVD Session Logoff Stall Timer" -Completed
                }
                Else { Show-Menu -Title ("No Active Sessions found") -Style Info -DisplayOnly -Color Green }

                # collects the number of running vm(s) to determine which to stop
                $vmsOnline = ($vmCollection.Where{$_.PowerState -eq "VM running"} | Measure-Object).Count
                # prevent this prompt by using -Confirm $false
                If ($PSCmdlet.ShouldProcess(("{0} Running WVD Session Hosts" -f $vmsOnline),("STOP and DEALLOCATE Virtual Machines in Group {0}" -f $SessionHostGroup.ToUpper()))) {
                    
                    # loop through each running vm and initiate the stop command without waiting - no need to wait as the portal should be used to validate the vm state
                    Write-Host ("`n`r")
                    $vmCollection.Where{$_.PowerState -eq "VM running"} | Foreach-Object {
                        $shName = $_.SessionHost.Name
                        $_ | Stop-AzVm -NoWait -Force | Select-Object @{l="Session Host Name";e={$shName}},@{l="Group";e={$SessionHostGroup}},@{l="Stop VM Status";e={$_.IsSuccessStatusCode}}
                    } | Format-Table -Autosize
                    
                    Write-Host ("-" * 120) -ForegroundColor Green
                    Write-Host ("-- Attempted to STOP and DEALLOCATE {0} virtual machines. Please verify state for each VM in the Azure Portal." -f $vmsOnline) -ForegroundColor Green
                    Write-Host ("-" * 120) -ForegroundColor Green
                }
                Else { Write-Warning "User aborted Stop-AzVM operation!" }
            }
            Else { Write-Warning "User aborted WVD Maintenance operation!" }
        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
    }
}

Function Disable-AzWvdMaintanence {
    <#
        .SYNOPSIS
            Puts a specific group of session hosts in a host pool into 'maintenance'
        .DESCRIPTION
            This function targets a specific host pool and group of session hosts, changes their Azure maintenance tag to TRUE and turns on drain mode to prevent new connections. Use of this function is for session host redeployment for monthly patching or session host recycling.
    #>
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
    Param (
        # Name of the Resource Group of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true,Position=0)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$ResourceGroupName,

        # Name of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true,Position=1)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.DesktopVirtualization/hostpools","ResourceGroupName")]
        [System.String]$HostPoolName,

        [Parameter(Mandatory=$false)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$LogAnalyticsResourceGroup,

        [Parameter(Mandatory=$false)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.OperationalInsights/workspaces","DeploymentResourceGroup")]
        [System.String]$LogAnalyticsWorkspace,

        # Group of Session Hosts to target (A or B)
        [Parameter(Mandatory=$true,Position=2)]
        [ValidateSet("A","B","ALL")]
        [String]$SessionHostGroup,

        [Parameter(ParameterSetName="SelfHosted")]
        [System.Guid]$CorrelationId,

        [Parameter(ParameterSetName="SelfHosted")]
        [Switch]$SelfHosted
    )
    BEGIN {
        #Requires -Modules @{ ModuleName = "Az.DesktopVirtualization"; ModuleVersion = "2.0.0" }
        
        $azContext = Get-AzContext
        $userName = ("{0} ({1})" -f $azContext.Account.Id,$azContext.Account.Type)
        If ($SelfHosted) {
            $ConfirmPreference = "None"
            $ProgressPreference = "SilentlyContinue"
            $VerbosePreference = "Continue"
            If (!$CorrelationId) {
                Write-Warning ("MISSING CORRELATIONID, LOGGING WILL BE COMPROMISED, CREATING NEW ID!")
                $CorrelationId = [System.Guid]::NewGuid()
            }
            If ($env:COMPUTERNAME -ne "GITHUBRUNNER" -AND $azContext.Account.Type -ne "ManagedService") {
                Write-Warning ("NOT EXECUTED FROM GITHUB ACTION RUNNER, ABORTING THE OPERATION!")
                Exit
            }
        }
        Else {
            If ($env:COMPUTERNAME -eq "GITHUBRUNNER" -AND $azContext.Account.Type -eq "ManagedService") {
                Write-Warning ("EXECUTED FROM GITHUB ACTION RUNNER, ENABLING SELFHOSTED SWITCH!")
                $SelfHosted = $true
                $ConfirmPreference = "None"
                $ProgressPreference = "SilentlyContinue"
                $VerbosePreference = "Continue"
            }
            If (!$CorrelationId) {
                Write-Warning ("MISSING CORRELATIONID, LOGGING WILL BE COMPROMISED, CREATING NEW ID!")
                $CorrelationId = [System.Guid]::NewGuid()
            }
        }
    }
    PROCESS {
        try {
            # variables for writing data to log analytics
            $azLogAnalyticsId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspace).CustomerId.ToString()
            $azLogAnalyticsKey = (Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspace).PrimarySharedKey
            # collection the virtual machines based on WVD-Group tag
            Write-Verbose ("[{0}] Gathering Virtual Machine data (Group: {1})" -f $ResourceGroupName,$SessionHostGroup.ToUpper())
            [System.Collections.Generic.List[System.Object]]$vmCollection = @()
            If ($SessionHostGroup -eq "ALL") { Get-AzVM -ResourceGroupName $ResourceGroupName -Status | ForEach-Object { $vmCollection.Add($_) | Out-Null } }
            Else { Get-AzVM -ResourceGroupName $ResourceGroupName -Status | Where-Object { $_.Tags["WVD-Group"] -eq $SessionHostGroup } | ForEach-Object { $vmCollection.Add($_) | Out-Null } }
            
            # loop through the virtual machines and add the session host information to the vm object
            $i = 0
            $sessionHostCount = 0
            Write-Verbose ("[{0}] Gathering Session Host data (Group: {1})" -f $HostPoolName,$SessionHostGroup.ToUpper())
            Foreach ($virtualMachine in $vmCollection) {
                Write-Progress -Activity ("[{0}] Gathering Session Host data (Group: {1})" -f $HostPoolName,$SessionHostGroup.ToUpper()) -Status ("Session Hosts Collected: {0}" -f $sessionHostCount) -CurrentOperation $virtualMachine.Name -PercentComplete (($i / $vmCollection.Count) * 100)
                # collect WVD session host objects
                $sessionHost = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName | Where-Object {$_.ResourceId -eq $virtualMachine.Id}
                # collect extension object data
                If ((Get-AzVMExtension -ResourceGroupName $virtualMachine.ResourceGroupName -VMName $virtualMachine.Name).Where{$_.Publisher -eq "Microsoft.Powershell" -and $_.ExtensionType -eq "DSC"}) {
                    $extensionStatus = Get-AzVMDscExtensionStatus -VMName $virtualMachine.Name -ResourceGroupName $virtualMachine.ResourceGroupName -ErrorAction SilentlyContinue
                }
                Else {
                    $extensionStatus = [PSCustomObject]@{StatusCode = "ProvisioningState/missing"}
                }
                
                If ($sessionHost) {
                    $sessionHostCount++
                    $virtualMachine | Add-Member -NotePropertyName SessionHost -NotePropertyValue $sessionHost
                    $virtualMachine | Add-Member -NotePropertyName ExtensionStatus -NotePropertyValue $extensionStatus
                    $virtualMachine | Add-Member -NotePropertyName Updated -NotePropertyValue $false
                }
                Else {
                    Write-Warning ("[{0}] Unable to match Virtual Machine object to Session Host object, removing the VM from processing collection!" -f $virtualMachine.Name)
                    If ($null -eq $missingVMs) {
                        $missingVMs = [System.Collections.Generic.List[System.Object]]@()
                        $missingVMs.Add($virtualMachine)
                    }
                    Else { $missingVMs.Add($virtualMachine) }
                }
                $i++
            }

            If ($missingVMs) { $missingVMs | ForEach-Object { $vmCollection.Remove($_) | Out-Null } }
            Write-Progress -Activity ("[{0}] Gathering Session Hosts from Group {1}" -f $HostPoolName,$SessionHostGroup.ToUpper()) -Completed
            

            If ($vmCollection.Count -eq 0) { Write-Warning "No Session Hosts found enabled for maintenance!" }
            Else {
                $vmMaintenanceHash = $vmCollection | Group-Object -Property {$_.Tags["WVD-Maintenance"]} -AsHashTable -AsString
                # prevent this prompt by using -Confirm $false
                If ($PSCmdlet.ShouldProcess(("{0} WVD Session Hosts" -f $vmMaintenanceHash["True"].Count),"DISABLE maintenace")) {
                    # loop through each vm in the collection, update the maintenance/dsc tag and turn off drain mode
                    If ($SessionHostGroup -eq "ALL") {
                        Write-Verbose ("[{0}] Updating Host Pool 'WVD-Maintenance' Tag" -f $HostPoolName)
                        $HostPool = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName
                        Update-AzTag -ResourceId $HostPool.Id -Tag @{"WVD-Maintenance" = $false} -Operation Merge | Out-Null
                        $logEntry = [PSCustomObject]@{
                            Timestamp = [DateTime]::UtcNow.ToString('o')
                            CorrelationId = $correlationId
                            Computer = $env:COMPUTERNAME
                            UserName = $userName
                            EntryType = "INFO"
                            Subscription = $azContext.Subscription.Name
                            ResourceGroupName = $ResourceGroupName
                            HostPoolName = $HostPoolName
                            SessionHostGroup = $SessionHostGroup.ToUpper()
                            SessionHostName = [System.String]::Empty
                            DscExtensionStatus = [System.String]::Empty
                            'WVD-Maintenance' = 'False'
                            'WVD-PostDscComplete' = [System.String]::Empty
                        }
                        New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_Maintenance_CL" -logMessage $logEntry -Verbose:$false
                    }

                    $x = 0
                    Foreach ($virtualMachine in $vmMaintenanceHash["True"]) {
                        Write-Verbose ("[{0}] Checking Session Host DSC Extension" -f $virtualMachine.Name)
                        Write-Progress -Id 42 -Activity ("[{0}] Updating Maintenance and DSC Tag" -f $HostPoolName) -Status ("Session Hosts Updated: {0}" -f $x) -CurrentOperation $virtualMachine.SessionHost.Name -PercentComplete (($x / $vmCollection.Count) * 100)
                        
                        If ($virtualMachine.ExtensionStatus.StatusCode -eq "ProvisioningState/succeeded") {
                            Write-Verbose ("[{0}] DSC Extension Status: {1}" -f $virtualMachine.Name,$virtualMachine.ExtensionStatus.StatusCode)
                            $tagUpdate = @{"WVD-Maintenance" = $false; "WVD-PostDscComplete" = $true}
                            Update-AzTag -ResourceId $virtualMachine.Id -Tag $tagUpdate -Operation Merge | Out-Null
                            $virtualMachine.Updated = $true
                            $x++
                            $logEntry = [PSCustomObject]@{
                                Timestamp = [DateTime]::UtcNow.ToString('o')
                                CorrelationId = $correlationId
                                Computer = $env:COMPUTERNAME
                                UserName = $userName
                                EntryType = "INFO"
                                Subscription = $azContext.Subscription.Name
                                ResourceGroupName = $ResourceGroupName
                                HostPoolName = $HostPoolName
                                SessionHostGroup = $SessionHostGroup.ToUpper()
                                SessionHostName = $virtualMachine.SessionHost.Name.Split("/")[-1]
                                DscExtensionStatus = $virtualMachine.ExtensionStatus.StatusCode
                                'WVD-Maintenance' = "False"
                                'WVD-PostDscComplete' = "True"
                            }
                            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_Maintenance_CL" -logMessage $logEntry -Verbose:$false
                        }
                        Else {
                            Write-Verbose ("[{0}] DSC Extension Status: {1}" -f $virtualMachine.Name,$virtualMachine.ExtensionStatus.StatusCode)
                            Write-Warning ("[{0}] DSC Extension did not provision successfully. Session Host will not be removed from maintenance!" -f $virtualMachine.SessionHost.Name.Split("/")[-1])
                            $logEntry = [PSCustomObject]@{
                                Timestamp = [DateTime]::UtcNow.ToString('o')
                                CorrelationId = $correlationId
                                Computer = $env:COMPUTERNAME
                                UserName = $userName
                                EntryType = "ERROR"
                                Subscription = $azContext.Subscription.Name
                                ResourceGroupName = $ResourceGroupName
                                HostPoolName = $HostPoolName
                                SessionHostGroup = $SessionHostGroup.ToUpper()
                                SessionHostName = $virtualMachine.SessionHost.Name.Split("/")[-1]
                                DscExtensionStatus = $virtualMachine.ExtensionStatus.StatusCode
                                'WVD-Maintenance' = "True"
                                'WVD-PostDscComplete' = "False"
                            }
                            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_Maintenance_CL" -logMessage $logEntry -Verbose:$false
                        }
                    }
                    Write-Progress -Id 42 -Activity ("[{0}] Updating Maintenance and DSC Tag" -f $HostPoolName) -Completed
                }
                Else { Write-Warning "User aborted WVD Maintenance operation!" }
            }
        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
    }
}

Function Remove-AzWvdResources {
    <#
        .SYNOPSIS
            Removes session hosts from host pools and deletes Azure resources
        .DESCRIPTION
            This function is used after session hosts have been put into 'maintenance'. This will remove session hosts from host pools and delete the virtual machine. Optionally, you can delete the attached NIC(s) and Disk(s).
    #>
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
    Param (
        # Name of the Resource Group of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true,Position=0)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$ResourceGroupName,

        # Name of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true,Position=1)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.DesktopVirtualization/hostpools","ResourceGroupName")]
        [System.String]$HostPoolName,

        # Group of Session Hosts to target (A or B)
        [Parameter(Mandatory=$true,Position=2)]
        [ValidateSet("A","B","ALL")]
        [String]$SessionHostGroup,

        # Also removes nic(s) and disk(s)
        [Switch]$IncludeAttachedResources
    )
    BEGIN {
        Function _CheckDeletionStatus {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
                [object]$objectDeletionURI,
                [Parameter(Mandatory=$true,Position=1)]
                [string]$azAccessToken

            )
            BEGIN {
                $objectDeletionCounter = [PSCustomObject]@{
                    Succeeded = 0
                    Failed = [System.Collections.Generic.List[System.Object]]@()
                    InProgress = 0
                    Unknown = 0
                }
            }
            PROCESS {
                try {
                    Write-Progress -ParentId 42 -Activity ("Verifying Azure Delete Operation") -Status $objectDeletionURI -CurrentOperation ("Succeeded: {0} | Failed: {1} | InProgress: {2} | Unknown: {3}" -f $objectDeletionCounter.Succeeded,$objectDeletionCounter.Failed.Count,$objectDeletionCounter.InProgress,$objectDeletionCounter.Unknown)
                    $objectDeletionContent = ((Invoke-WebRequest -Method Get -Headers @{"Authorization" = "Bearer " + $azAccessToken} -Uri $objectDeletionURI -Verbose:$false).Content | ConvertFrom-Json)
                }
                catch {
                    [System.Console]::ForegroundColor = "Red"
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.SystemException]::new("Failed to get virtual machine deletion status"),
                        "ObjectDeletionStatus",
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $objectDeletionURI
                    )
                    [System.Console]::ResetColor()
                }
                
                Switch ($objectDeletionContent.Status) {
                    "Succeeded" { $objectDeletionCounter.Succeeded++ }
                    "Cancelled" {
                        $objectDeletionCounter.Failed.Add($objectDeletionURI)
                        [System.Console]::ForegroundColor = "Red"
                        [System.Management.Automation.ErrorRecord]::new(
                            [System.SystemException]::new("Virtual machine deletion cancelled"),
                            "ObjectDeletionCancelled",
                            [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                            $objectDeletionURI
                        )
                        [System.Console]::ResetColor()
                    }
                    "Failed" {
                        $objectDeletionCounter.Failed.Add($objectDeletionURI)
                        [System.Console]::ForegroundColor = "Red"
                        [System.Management.Automation.ErrorRecord]::new(
                            [System.SystemException]::new("Virtual machine deletion failed"),
                            "ObjectDeletionFailed",
                            [System.Management.Automation.ErrorCategory]::OperationStopped,
                            $objectDeletionURI
                        )
                        [System.Console]::ResetColor()
                    }
                    "InProgress" { $objectDeletionCounter.InProgress++ }
                    Default { 
                        $objectDeletionCounter.Unknown++ 
                        Write-Warning $objectDeletionContent.Status
                    }
                }
                Start-Sleep -Milliseconds 2500
            }
            END {
                return $objectDeletionCounter
            }
        }
    }
    PROCESS {
        try {
            # collection the virtual machines based on WVD-Group tag
            If($SessionHostGroup -eq "ALL") { $vmCollection = Get-AzVM -ResourceGroupName $ResourceGroupName -Status }
            Else { $vmCollection = Get-AzVM -ResourceGroupName $ResourceGroupName -Status | Where-Object {$_.Tags["WVD-Group"] -eq $SessionHostGroup} }
            
            # loop through the virtual machines and add the session host information to the vm object
            $i = 0
            $sessionHostCount = 0
            Foreach ($virtualMachine in $vmCollection) {
                Write-Progress -Activity ("[{0}] Gathering Session Hosts from Group {1}" -f $HostPoolName,$SessionHostGroup.ToUpper()) -Status ("Virtual Machines Collected: {0}" -f $i) -CurrentOperation $virtualMachine.Name -PercentComplete (($i / $vmCollection.Count) * 100)
                $sessionHost = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName | Where-Object {$_.ResourceId -eq $virtualMachine.Id}
                
                If ($sessionHost) {
                    $sessionHostCount++
                    $virtualMachine | Add-Member -NotePropertyName SessionHost -NotePropertyValue $sessionHost
                }
                $i++
            }
            Write-Progress -Activity ("[{0}] Gathering Session Hosts from Group {1}" -f $HostPoolName,$SessionHostGroup.ToUpper()) -Completed

            # separate messages based on removing attached resources
            If ($IncludeAttachedResources) { $message = ("REMOVE and DELETE Session Host(s) and attached resources (VM, OsDisk, Nic)" -f $HostPoolName) }
            Else { $message = ("REMOVE and DELETE Session Host(s) (VM ONLY)" -f $HostPoolName) }

            # prevent this prompt by using -Confirm $false
            If ($PSCmdlet.ShouldProcess(("{0} WVD Session Host(s)" -f $vmCollection.Count),$message)) {
                # loop through each vm in the collection, remove from host pool, delete the vm, and optionally delete the nic and os disk
                $i = 0
                $accessToken = Create-AccessToken
                [System.Collections.Generic.List[System.Object]]$attachedResources = @()
                [System.Collections.Generic.List[System.Object]]$attachedResourcesDeletionURIs = @()
                [System.Collections.Generic.List[System.Object]]$vmDeletionURIs = @()
                Foreach ($virtualMachine in $vmCollection) {
                    Write-Progress -Activity "Windows Virtual Desktop - Azure Resource Clean Up" -Status ("Virtual Machine: {0} ({1} of {2})" -f $virtualMachine.Name,$i,$vmCollection.Count) -CurrentOperation ("Removing Session Host from Host Pool") -PercentComplete (($i / $vmCollection.Count) * 100)
                    If ($virtualMachine.SessionHost) {
                        Write-Verbose ("[{0}] Removing Session Host object from Host Pool")
                        Remove-AzWvdSessionHost -Name $virtualMachine.SessionHost.Name.Split("/")[-1] -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -Force | Out-Null
                    }
                    Else { Write-Warning ("[{0}] Virtual Machine does not have a Session Host object" -f $virtualMachine.Name) }

                    $virtualMachine.NetworkProfile.NetworkInterfaces | ForEach-Object { $attachedResources.Add($_.Id) }
                    $attachedResources.Add( $virtualMachine.StorageProfile.OsDisk.ManagedDisk.Id )      
                    
                    try {
                        Write-Progress -Activity "Windows Virtual Desktop - Azure Resource Clean Up" -Status ("Virtual Machine: {0} ({1} of {2})" -f $virtualMachine.Name,$i,$vmCollection.Count) -CurrentOperation ("Removing Virutal Machine") -PercentComplete (($i / $vmCollection.Count) * 100)
                        $vmDeletion = Invoke-WebRequest -Method Delete -Headers @{"Authorization" = "Bearer " + $accessToken} -Uri ("https://management.azure.com{0}?api-version=2020-06-01" -f $virtualMachine.Id) -Verbose:$false
                        $vmDeletionURIs.Add(($vmDeletion.RawContent.Split("`n") | Select-String -Pattern "Azure-AsyncOperation").Line.split(" ")[-1])
                    }
                    catch {
                        [System.Console]::ForegroundColor = "Red"
                        [System.Management.Automation.ErrorRecord]::new(
                            [System.SystemException]::new("Failed to delete virtual machine"),
                            "VMDeletionFailed",
                            [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                            $virtualMachine.Name
                        )
                        [System.Console]::ResetColor()
                    }
                    $i++
                }

                while ($true) {
                    Write-Progress -Id 42 -Activity "Windows Virtual Desktop - Validate Azure Resource Deletion" -Status ("Virutal Machine: ({0} of {1})" -f $deletionResults.Succeeded,$vmDeletionURIs.Count) -CurrentOperation ("Waiting on deletion of Azure Virtual Machine(s)") -PercentComplete (($deletionResults.Succeeded / $vmDeletionURIs.Count) * 100)
                    $deletionResults = $vmDeletionURIs | _CheckDeletionStatus -azAccessToken $accessToken
                    If($deletionResults.Failed.Count -gt 0) { $deletionResults.Failed | ForEach-Object { $vmDeletionURIs.Remove($_) | Out-Null } }
                    If($deletionResults.Succeeded -eq $vmDeletionURIs.Count) { break }
                    Start-Sleep -Seconds 2
                }
                $deletionResults = $null

                If ($IncludeAttachedResources) {
                    $x = 0
                    foreach ($attachedResource in $attachedResources) {
                        try {
                            Write-Progress -Activity "Windows Virtual Desktop - Azure Resource Clean Up" -Status ("Attached Resource: ({0} of {1})" -f $x,$attachedResources.Count) -CurrentOperation ("Deleting Azure Disk(s) and Virtual Network Interface(s)") -PercentComplete (($x / $attachedResources.Count) * 100)
                            $attachedResourceDeletion = Invoke-WebRequest -Method Delete -Headers @{"Authorization" = "Bearer " + $accessToken} -Uri ("https://management.azure.com{0}?api-version=2019-07-01" -f $attachedResource)
                            $attachedResourcesDeletionURIs.Add( ($attachedResourceDeletion.RawContent.Split("`n") | Select-String -Pattern "Azure-AsyncOperation").Line.split(" ")[-1] )
                        }
                        catch {
                            [System.Console]::ForegroundColor = "Red"
                            [System.Management.Automation.ErrorRecord]::new(
                                [System.SystemException]::new("Failed to delete virtual machine attached object"),
                                "VMAttachedObjectDeletionFailed",
                                [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                                $attachedResource
                            )
                            [System.Console]::ResetColor()
                            Continue
                        }
                        $x++
                    }
                    while ($true) {
                        Write-Progress -Id 42 -Activity "Windows Virtual Desktop - Validate Azure Resource Deletion" -Status ("Attached Resource: ({0} of {1})" -f $deletionResults.Succeeded,$attachedResourcesDeletionURIs.Count) -CurrentOperation ("Waiting on deletion of Azure Disk(s) and Virtual Network Interface(s)") -PercentComplete (($deletionResults.Succeeded / $attachedResourcesDeletionURIs.Count) * 100)
                        $deletionResults = $attachedResourcesDeletionURIs | _CheckDeletionStatus -azAccessToken $accessToken
                        If($deletionResults.Failed.Count -gt 0) { $deletionResults.Failed | ForEach-Object { $attachedResourcesDeletionURIs.Remove($_) | Out-Null } }
                        If($deletionResults.Succeeded -eq $attachedResourcesDeletionURIs.Count) { break }
                        Start-Sleep -Seconds 2                  }
                }
                Write-Progress -Activity "Progress Complete"  -Completed
                
                Write-Host ("`n`r")
                Write-Host ("-" * 120) -ForegroundColor Green
                Write-Host ("-- Attempted to REMOVE and DELETE {0} WVD Virtual Machines and associated objects. Please validate using PowerShell or Azure Portal." -f $vmCollection.Count) -ForegroundColor Green
                Write-Host ("-" * 120) -ForegroundColor Green
            }
            Else { Write-Warning "User aborted clean up operation!" }

        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
    }
}

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
            If ($env:COMPUTERNAME -eq "GITHUBRUNNER" -AND $azContext.Account.Type -eq "ManagedService") {
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
                $scaleUnitTemplate = Get-FileNameDialog -InitialDirectory [system.io.path]::GetDirectoryName($MyInvocation.PSScriptRoot)
                Write-Verbose "`t $scaleUnitTemplate"
                Show-Menu -Title "Select Scale Unit ARM Parameter File" -Style Info -Color Cyan -DisplayOnly
                $scaleUnitParameters = Get-FileNameDialog -InitialDirectory [system.io.path]::GetDirectoryName($MyInvocation.PSScriptRoot)
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
        $wvdHostPoolTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "Deploy-WVD-HostPool.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $wvdSessionHostTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "Deploy-WVD-SessionHosts.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $DscTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob ("Deploy-WVD-Config.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $DscTemplateParamUri = New-AzStorageBlobSASToken -Container templates -Blob ("Deploy-WVD-Config.parameters.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
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
                HostPoolName = [System.String]::Empty
            }
            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false

            $wvdDscConfigZipUrl = Get-LatestWVDConfigZip -OutputType Local -LocalPath $deploymentParameters.parameters.wvd_hostPoolConfig.value.configs[0].wvdArtifactLocation

            [System.Collections.ArrayList]$deploymentJobs = @()
            Foreach ($hostPool in $outputHash.Keys) {

                $dscZipUri = New-AzStorageBlobSASToken -Container dsc -Blob $outputHash[$hostPool].dscConfiguration -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri

                Write-Host ("[{0}] Host Pool: {1} | Generating Host Pool registration token..." -f (Get-Date), $hostPool)
                $wvdHostPoolToken = New-AzWvdRegistrationInfo -ResourceGroupName $outputHash[$hostPool].resourceGroupName -HostPoolName $hostPool -ExpirationTime $expirationTime
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
                    HostPoolName = $hostPool
                }
                New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false

                $templateParams = [Ordered]@{
                    Name = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                    az_virtualMachineNames = $vmNames
                    wvd_dscConfigurationScript = $outputHash[$hostPool].dscConfiguration.Trim(".zip")
                    wvd_dscConfigZipUrl = $wvdDscConfigZipUrl
                    wvd_deploymentType = $outputHash[$hostPool].deploymentType
                    wvd_deploymentFunction = $outputHash[$hostPool].deploymentFunction
                    wvd_fsLogixVHDLocation = $outputHash[$hostPool].fsLogixVhdLocation
                    wvd_ArtifactLocation = $outputHash[$hostPool].wvdArtifactLocation
                    wvd_hostPoolName = $hostPool
                    wvd_hostPoolToken = $wvdHostPoolToken.Token
                    wvd_sessionHostDSCModuleZipUri = $dscZipUri
                    ResourceGroupName = $outputHash[$hostPool].resourceGroupName
                    TemplateUri = $DscTemplateUri
                    TemplateParameterFile = ("{0}\dsc.parameters.json" -f $env:TEMP)
                }
                
                Write-Debug ("Start Configuration: {0}" -f $hostPool)
                $deploymentJob = New-AzResourceGroupDeployment @templateParams -AsJob
                If ($deploymentJob) {
                    try {
                        While ($true) {
                            If (Get-AzResourceGroupDeployment -ResourceGroupName $outputHash[$hostPool].resourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString) -ErrorAction SilentlyContinue) { Break }
                            Else {
                                Write-Verbose ("[{0}] Waiting for job: Deploy-WVD-DscConfiguration-{1}" -f (Get-Date),$deploymentString)
                                Start-Sleep -Seconds 5
                            }
                        }

                        $deploymentInfo = Get-AzResourceGroupDeployment -ResourceGroupName $outputHash[$hostPool].resourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                        $logEntry = [PSCustomObject]@{
                            Timestamp = [DateTime]::UtcNow.ToString('o')
                            CorrelationId = $correlationId
                            Computer = $env:COMPUTERNAME
                            UserName = $userName
                            EntryType = "INFO"
                            Subscription = $subscriptionName
                            ResourceGroupName = $outputHash[$hostPool].resourceGroupName
                            DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                            DeploymentStatus = $deploymentInfo.ProvisioningState
                            HostPoolName = $hostPool
                        }
                        New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                        [Void]$deploymentJobs.Add($deploymentJob)
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
                            ResourceGroupName = $outputHash[$hostPool].resourceGroupName
                            DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                            DeploymentStatus = $_.Exception.Message
                            HostPoolName = $hostPool
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
                        ResourceGroupName = $outputHash[$hostPool].resourceGroupName
                        DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                        DeploymentStatus = "NotStarted"
                        HostPoolName = $hostPool
                    }
                    New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                    Return
                }
            }

            $currentTime = [DateTime]::UtcNow
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            Do {
                $i = 0
                [System.Collections.Generic.List[System.Object]]$Jobs = @()
                Foreach ($resourceGroup in $Output.ResourceGroupName) {
                    $job = Get-AzResourceGroupDeployment -ResourceGroupName $resourceGroup -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                    
                    If ($job.ProvisioningState -eq "Running") {$i++}
                    $elapsedTime = $job.TimeStamp.ToUniversalTime() - $currentTime.ToUniversalTime()
                    $obj = [PSCustomObject][Ordered]@{
                        Name = ("Deploy-WVD-DscConfiguration-{0}  " -f $deploymentString)
                        ResourceGroup = ("{0}  " -f $resourceGroup)
                        Status = ("{0}  " -f $job.ProvisioningState)
                        Duration = ("{0:N0}.{1:N0}:{2:N0}:{3:N0}" -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds)
                    }
                    $Jobs.Add($obj)
                }

                If ($SelfHosted) { Write-Host "." -NoNewline }
                Else {
                    Show-Menu -Title ("Job Status") -DisplayOnly -Style Info -Color Cyan -ClearScreen
                    $Jobs | Sort-Object 'ResourceGroup' -Descending | Format-Table -AutoSize | Out-Host
                    
                    Write-Host "`n`rNext refresh in " -NoNewline
                    Write-Host "5" -ForegroundColor Magenta -NoNewline
                    Write-Host " Seconds`r`n"
                }
                If ($stopWatch.Elapsed.TotalMinutes -gt 89) { Write-Warning ("One or More of the Deployment Jobs has exceeded a 90 minutes deployment time!") }
                Start-Sleep -Seconds 5

            } Until ($i -eq 0)
            Write-Host "Done!`n`r"

            Foreach ($resourceGroup in $Output.ResourceGroupName) {
                $job = Get-AzResourceGroupDeployment -ResourceGroupName $resourceGroup -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                
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
                    ResourceGroupName = $resourceGroup
                    DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                    DeploymentStatus = $job.ProvisioningState
                    HostPoolName = $job.Parameters.wvd_hostPoolName.Value
                }
                New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
                If ($SelfHosted) {
                    Disable-AzWvdMaintanence -ResourceGroupName $resourceGroup -HostPoolName $job.Parameters.wvd_hostPoolName.Value -SessionHostGroup ALL -LogAnalyticsResourceGroup $DeploymentResourceGroup -LogAnalyticsWorkspace $LogAnalyticsWorkspace -CorrelationId $correlationId -SelfHosted
                }
                Else {
                    Disable-AzWvdMaintanence -ResourceGroupName $resourceGroup -HostPoolName $job.Parameters.wvd_hostPoolName.Value -SessionHostGroup ALL -LogAnalyticsResourceGroup $DeploymentResourceGroup -LogAnalyticsWorkspace $LogAnalyticsWorkspace -CorrelationId $correlationId
                }
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
                ResourceGroupName = $outputHash[$hostPool].resourceGroupName
                DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                DeploymentStatus = $Results.ProvisioningState
                HostPoolName = $hostPool
            }
            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
        }
    }
}

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
        [System.String]$StorageAccountResourceGroup,

        [Parameter(Mandatory=$false)]
        [System.String]$StorageAccountSubscription,

        [Parameter(Mandatory=$false)]
        [System.String]$StorageAccountName
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
        
        $wvdSessionHostTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "Deploy-WVD-SessionHosts.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $wvdHostPoolExpansionTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "Expand-WVD-HostPool.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $wvdHostPoolExpansionParamUri = New-AzStorageBlobSASToken -Container templates -Blob "Expand-WVD-HostPool.parameters.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        (New-Object System.Net.WebClient).DownloadFile($wvdHostPoolExpansionParamUri,("{0}\wvd.parameters.json" -f $env:TEMP))
        
        $DscTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob ("Deploy-WVD-Config.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $DscTemplateParamUri = New-AzStorageBlobSASToken -Container templates -Blob ("Deploy-WVD-Config.parameters.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
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

            $wvdDscConfigZipUrl = Get-LatestWVDConfigZip -LocalPath "\\SERVER\SHARE"

            $dscZipUri = New-AzStorageBlobSASToken -Container dsc -Blob ("{0}" -f $HostPool.Tag["WVD-DscConfiguration"]) -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri

            Write-Host ("[{0}] Host Pool: {1} | Generating Host Pool registration token..." -f (Get-Date), $HostPoolName)
            $wvdHostPoolToken = New-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -ExpirationTime $expirationTime
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
                wvd_hostPoolToken = $wvdHostPoolToken.Token
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
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Storage/storageAccount","StorageAccountResourceGroup")]
        [System.String]$StorageAccountName,

        # Name of the Resource Group of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$VirtualNetworkResourceGroup,

        # Name of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Storage/storageAccount","StorageAccountResourceGroup")]
        [System.String]$VirtualNetworkName,

        # Name of the Resource Group of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$LogAnalyticsResourceGroup,

        # Name of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.OperationalInsights/Workspace","LogAnalyticsResourceGroup")]
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
        
        $wvdSessionHostTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob "Deploy-WVD-SessionHosts.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $wvdSessionHostTemplateParamUri = New-AzStorageBlobSASToken -Container templates -Blob "Deploy-WVD-SessionHosts.parameters.json" -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        (New-Object System.Net.WebClient).DownloadFile($wvdSessionHostTemplateParamUri,("{0}\wvd.parameters.json" -f $env:TEMP))
        Start-Sleep -Seconds 5
        $DscTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob ("Deploy-WVD-Config.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        $DscTemplateParamUri = New-AzStorageBlobSASToken -Container templates -Blob ("Deploy-WVD-Config.parameters.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
        (New-Object System.Net.WebClient).DownloadFile($DscTemplateParamUri,("{0}\dsc.parameters.json" -f $env:TEMP))

        $wvdContext = Set-AzContext -Subscription $subscriptionName
        Write-Host ("`tConnected to: {0}, using {1}" -f $wvdContext.Name.Split("(")[0].Trim(" "),$wvdContext.Account.Id)
        $azLogAnalyticsId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspace -WarningAction SilentlyContinue).CustomerId.ToString()
        $azLogAnalyticsKey = (Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspace -WarningAction SilentlyContinue).PrimarySharedKey

        $HostPool = Get-AzWvdHostPool -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName
        $vmTemplate = $HostPool.VMTemplate | ConvertFrom-Json
        $subnetId = Get-AzVirtualNetwork -Name $VirtualNetworkName -ResourceGroupName $VirtualNetworkResourceGroup | Get-AzVirtualNetworkSubnetConfig -Name ("WVD-Subnet-{0}" -f $HostPoolName.Split("-")[-1]) | Select-Object -ExpandProperty Id

        Write-Host ("[{0}] Starting WVD Session Host Deployment..." -f (Get-Date))
        $correlationId = [Guid]::NewGuid()
        $deploymentString = $correlationId.Guid.Split("-")[-1]

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
                HostPoolName = [System.String]::Empty
            }
            New-AzWvdLogEntry -customerId $azLogAnalyticsId -sharedKey $azLogAnalyticsKey -logName "WVD_AutomatedDeployments_CL" -logMessage $logEntry -Verbose:$false
            $vmNames = Get-AzVM -ResourceGroupName $ResourceGroupName -Status | Where-Object { $_.Tags["WVD-Group"] -eq $SessionHostGroup } | ForEach-Object { $_.Name }
            $wvdDscConfigZipUrl = Get-LatestWVDConfigZip -OutputType Remote -Verbose:$false
            $dscZipUri = New-AzStorageBlobSASToken -Container dsc -Blob $hostPool.Tag["WVD-DscConfiguration"] -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri

            Write-Host ("[{0}] Host Pool: {1} | Generating Host Pool registration token..." -f (Get-Date), $HostPoolName)
            $wvdHostPoolToken = New-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -ExpirationTime $expirationTime
            
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
                wvd_dscConfigurationScript = $hostPool.Tag["WVD-DscConfiguration"].Trim(".zip")
                wvd_dscConfigZipUrl = $wvdDscConfigZipUrl
                wvd_deploymentType = $HostPool.Tag["WVD-Deployment"]
                wvd_deploymentFunction = $HostPool.Tag["WVD-Function"]
                wvd_fsLogixVHDLocation = $HostPool.Tag["WVD-FsLogixVhdLocation"]
                wvd_ArtifactLocation = $HostPool.Tag["WVD-ArtifactLocation"]
                wvd_hostPoolName = $HostPoolName
                wvd_hostPoolToken = $wvdHostPoolToken.Token
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
                        ResourceGroupName = $outputHash[$hostPool].resourceGroupName
                        DeploymentName = ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                        DeploymentStatus = $_.Exception.Message
                        HostPoolName = $hostPool
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
                $job = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                
                If ($job.ProvisioningState -eq "Running") {$i++}
                
                $elapsedTime = $job.TimeStamp.ToUniversalTime() - $currentTime.ToUniversalTime()
                $objJob = [PSCustomObject][Ordered]@{
                    Name = ("Deploy-WVD-DscConfiguration-{0}  " -f $deploymentString)
                    ResourceGroup = ("{0}  " -f $ResourceGroupName)
                    Status = ("{0}  " -f $job.ProvisioningState)
                    Duration = ("{0:N0}.{1:N0}:{2:N0}:{3:N0}" -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds)
                }

                If ($SelfHosted) { Write-Host "." -NoNewline }
                Else {
                    Show-Menu -Title ("Job Status") -DisplayOnly -Style Info -Color Cyan -ClearScreen
                    $objJob | Format-Table -AutoSize
                    
                    Write-Host "`n`rNext refresh in " -NoNewline
                    Write-Host "5" -ForegroundColor Magenta -NoNewline
                    Write-Host " Seconds`r`n"
                }
                If ($stopWatch.Elapsed.TotalMinutes -gt 89) {
                    Write-Warning ("The Deployment Job has exceeded a 90 minutes deployment time!")
                    Break
                }
                Start-Sleep -Seconds 5

            } Until ($i -eq 0)
            Write-Host "Done!`n`r"

            $job = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name ("Deploy-WVD-DscConfiguration-{0}" -f $deploymentString)
                
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

Function New-AzWvdSessionHostConfig {
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
    Param (
        [Parameter(Mandatory=$true)]
        [String]$SubscriptionName,

        [Parameter(Mandatory=$true)]
        [String]$Location,

        [Parameter(Mandatory=$true)]
        [ValidateSet("A","B","ALL")]
        [String]$SessionHostGroup,

        [Parameter(Mandatory=$false)]
        [System.String]$StorageAccountResourceGroup,

        [Parameter(Mandatory=$false)]
        [System.String]$StorageAccountSubscription,

        [Parameter(Mandatory=$false)]
        [System.String]$StorageAccountName
    )

    BEGIN {

        $expirationTime = (Get-Date).AddHours(12)
        $wvdConfigZipPath = "\\SERVER\SHARE"
        $coreAzContext = Set-AzContext -Subscription $StorageAccountSubscription
        $stgAccountContext = (Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroup -DefaultProfile $coreAzContext).Context
        $wvdDscConfigZipUrl = Get-LatestWVDConfigZip -Path $wvdConfigZipPath

    }
    PROCESS {
        
        Set-AzContext -Subscription $SubscriptionName | Out-Null
        [System.Collections.ArrayList]$deploymentJobs = @()
        
        Do {
            Write-Verbose "Getting WVD Host Pools..."
            $HPs = Get-AzWvdHostPool -Verbose:$false -Debug:$false | Select-Object @{l="Name";e={$_.Name.Split("/")[-1]}},@{l="ResourceGroupName";e={$_.Id.Split("/")[4]}},Tag,Description
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
            Write-Host ("Host Pool: {0}" -f $HPs[$HPChoice].Name)
            Write-Host ("Host Pool: {0} | Generating Host Pool registration token and fetch Configuration URL(s)" -f $HPs[$HPChoice].Name)

            $deploymentString = ([Guid]::NewGuid()).Guid.Split("-")[-1]
            $DscConfiguration = $HPs[$HPChoice].Tag["WVD-DscConfiguration"]
            $FsLogixVhdLocation = $HPs[$HPChoice].Tag["WVD-FsLogixVhdLocation"]
            $Properties = $HPs[$HPChoice].Description.replace("\","\\") | ConvertFrom-Json
            $dscZipUri = New-AzStorageBlobSASToken -Container dsc -Blob $DscConfiguration -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
            $DscTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob ("Deploy-WVD-Config.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
            $DscTemplateParamUri = New-AzStorageBlobSASToken -Container templates -Blob ("Deploy-WVD-Config.parameters.json") -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
            (New-Object System.Net.WebClient).DownloadFile($DscTemplateParamUri,("{0}\dsc.parameters.json" -f $env:TEMP))
            $wvdHostPoolToken = New-AzWvdRegistrationInfo -ResourceGroupName $HPs[$HPChoice].ResourceGroupName -HostPoolName $HPs[$HPChoice].Name -ExpirationTime $expirationTime
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
        
            Write-Host ("Host Pool: {0} | Starting WVD Session Host Configuration (AsJob)..." -f $HPs[$HPChoice].Name)
            
            $templateParams = [Ordered]@{
                Name = $deploymentName
                az_virtualMachineNames = $vmNames
                az_vmImagePublisher = $Properties.imagePublisher
                wvd_dscConfigurationScript = $DscConfiguration.Trim(".zip")
                wvd_dscConfigZipUrl = $wvdDscConfigZipUrl
                wvd_deploymentType = $HPs[$HPChoice].Tag["WVD-Deployment"]
                wvd_deploymentFunction = $HPs[$HPChoice].Tag["WVD-Function"]
                wvd_fsLogixVHDLocation = $FsLogixVhdLocation
                wvd_ArtifactLocation = "\\SERVER\SHARE"
                wvd_hostPoolName = $HPs[$HPChoice].Name
                wvd_hostPoolToken = $wvdHostPoolToken.Token
                wvd_sessionHostDSCModuleZipUri = $dscZipUri
                ResourceGroupName = $HPs[$HPChoice].ResourceGroupName
                TemplateUri = $DscTemplateUri
                TemplateParameterFile = ("{0}\dsc.parameters.json" -f $env:TEMP)
            }

            If ($PSCmdlet.ShouldProcess($HPs[$HPChoice].Name,"Initiate DSC Configuration Deployment")) {
                $deploymentJob = New-AzResourceGroupDeployment @templateParams -AsJob
                [Void]$deploymentJobs.Add($deploymentJob)
                Write-Host ("Active Deployment Jobs: {0}" -f $deploymentJobs.Count)
            }
            Else {Write-Host "Configuration cancelled!"}
            $Done = Get-ChoicePrompt -Title "`n" -Message "Select another WVD Host Pool Group?" -OptionList "&Yes","&No"
        } Until ($Done -eq 1)

        If ($deploymentJobs.Count -gt 0) {
            Show-Menu -Title "WVD Configuration Deployments" -DisplayOnly -ClearScreen -Color White -Style Info
            _WaitOnJobs -Jobs $deploymentJobs -maxDuration 90
        }
    }
}

Function Get-MsiProductInfo {
    [CmdletBinding()]
    Param (
        [System.String]$msiPath
    )

    # Definition
    $sig = @'
    [DllImport("msi.dll", CharSet = CharSet.Unicode, PreserveSig = true, SetLastError = true, ExactSpelling = true)]
    private static extern UInt32 MsiOpenPackageW(string szPackagePath, out IntPtr hProduct);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, PreserveSig = true, SetLastError = true, ExactSpelling = true)]
    private static extern uint MsiCloseHandle(IntPtr hAny);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, PreserveSig = true, SetLastError = true, ExactSpelling = true)]
    private static extern uint MsiGetPropertyW(IntPtr hAny, string name, StringBuilder buffer, ref int bufferLength);
    private static string GetPackageProperty(string msi, string property)
    {
        IntPtr MsiHandle = IntPtr.Zero;
        try
        {
            var res = MsiOpenPackageW(msi, out MsiHandle);
            if (res != 0)
            {
                return null;
            }
            int length = 256;
            var buffer = new StringBuilder(length);
            res = MsiGetPropertyW(MsiHandle, property, buffer, ref length);
            return buffer.ToString();
        }
        finally
        {
            if (MsiHandle != IntPtr.Zero)
            {
                MsiCloseHandle(MsiHandle);
            }
        }
    }
    public static string GetProductCode(string msi)
    {
        return GetPackageProperty(msi, "ProductCode");
    }
    public static string GetProductName(string msi)
    {
        return GetPackageProperty(msi, "ProductName");
    }
'@
    $msiTools = Add-Type -PassThru -Namespace 'Microsoft.Windows.DesiredStateConfiguration.PackageResource' -Name 'MsiTools' -Using 'System.Text' -MemberDefinition $sig


    # Get the MSI Product Name
    $msiProductName = $msiTools::GetProductName($msiPath)
    # Get the MSI Product ID / GUID
    $msiProductGuid = $msiTools::GetProductCode($msiPath)

    $output = [PSCustomObject][Ordered]@{
        ProductName = $msiProductName
        ProductGuid = $msiProductGuid
    }

    Return $output
}

Function Invoke-AzWvdSessionManager {
    [CmdletBinding()]
    Param (
        # Name of the Subscription for the WVD resources to be deployed (supports tab completion)
        [Parameter(Mandatory=$true)]
        [ArgumentCompleter({
            Param($CommandName,$ParameterName,$WordsToComplete,$CommandAst,$FakeBoundParameters)
            Get-AzSubscription | Where-Object {$_.Name -like "$WordsToComplete*"} | Select-Object -ExpandProperty Name
        })]
        [String]$SubscriptionName,

        # Azure region location of the resources and resource groups
        [Parameter(Mandatory=$true)]
        [ArgumentCompleter({
            Param($CommandName,$ParameterName,$WordsToComplete,$CommandAst,$FakeBoundParameters)
            Get-AzLocation | Where-Object {$_.Location -like "$WordsToComplete*"} | Select-Object -ExpandProperty Location
        })]
        [String]$Location
    )
    BEGIN {
        #Requires -Modules Az.Accounts,Az.DesktopVirtualization
        Function _GetAzWvdUserSessions {
            Write-Host (" Getting Windows Virtual Desktop Host Pools...")
            $HPs = Get-AzWvdHostPool -Verbose:$false -Debug:$false | Select-Object @{l="Name";e={$_.Name.Split("/")[-1]}},@{l="ResourceGroupName";e={$_.Id.Split("/")[4]}}
            If ($HPs.Count -gt 0) {
                Write-Host ("  >> Found {0} Windows Virtual Desktop Host Pools" -f $HPs.Count)
                [System.Collections.ArrayList]$Sessions = @()
                Foreach ($HP in $HPs) {
                    Write-Host ("  >> [{0}] Collecting Host Pool User Session Information" -f $HP.Name)
                    Get-AzWvdUserSession -HostPoolName $HP.Name -ResourceGroupName $HP.ResourceGroupName | ForEach-Object {
                        $sessionObject = [PSCustomObject][Ordered]@{
                            UserPrincipalName = $_.UserPrincipalName
                            UserName = $_.ActiveDirectoryUserName
                            HostPool = $HP.Name
                            ResourceGroupName = $HP.ResourceGroupName
                            SessionHost = $_.Name.Split("/")[1]
                            Id = $_.Name.Split("/")[-1]
                            Duration = ([DateTime]::Now).Subtract($_.CreateTime.ToLocalTime())
                            SessionState = $_.SessionState
                        }
                        [Void]$Sessions.Add($sessionObject)
                    }
                }
                Write-Host "`n`r"
                Write-Verbose ("Collected {0} User Sessions from {1} Host Pools" -f $Sessions.Count,$HPs.Count)
                Return $Sessions
            }
            Else {
                Write-Warning ("No WVD Host Pools found in the {0} Subscription" -f $SubscriptionName)
                Return
            }
        }
    }
    PROCESS {
        Show-Menu -Title (" Windows Virtual Desktop User Session Manager") -Style Full -Color White -ClearScreen -DisplayOnly
        Set-AzContext -Subscription $SubscriptionName | Out-Null
        
        Do {
            If ($null -eq $Sessions) { $Sessions = _GetAzWvdUserSessions }
            Else {
                Write-Warning ("User Session data is not empty ({0} Sessions)" -f $Sessions.Count)
                Switch (Get-ChoicePrompt -Message "`nDo you want to get a fresh collection of User Sessions?" -OptionList "&Yes","&No" -Default 1) {
                    0 {
                        Clear-Host
                        $Sessions = _GetAzWvdUserSessions
                    }
                    1 {
                        Clear-Host
                        Write-Verbose ("Using current User Session data ({0} Sessions)" -f $Sessions.Count)
                    }
                }
            }
            
            If ($Sessions.Count -eq 0) { Write-Warning ("No User Sessions Found") }
            Else {
                $HostPools = $Sessions | Group-Object HostPool -NoElement -AsHashTable -AsString
                Show-Menu -Title (" Found {0} User Sessions from {1} Host Pools" -f $Sessions.Count,$HostPools.Count) -Style Mini -Color Yellow -DisplayOnly
                Switch (Get-ChoicePrompt -Message "Search by UserName or UserPrincipalName?" -OptionList "&UserName","User&PrincipalName","&Quit" -Default 1) {
                    0 {
                        $property = "UserName"
                        $searchString = Show-Menu -Title " Enter the full or partial Active Directory UserName" -Menu "UserName" -Style Info -Color Cyan
                    }
                    1 {
                        $property = "UserPrincipalName"
                        $searchString = Show-Menu -Title " Enter the full or partial Active Directory UserPrincipalName" -Menu "UserPrincipalName" -Style Info -Color Cyan
                    }
                    2 { Return }
                }
                $sessionMatches = $Sessions.Where{$_.$property -match $searchString}
                Write-Verbose ("Found {0} Sessions by {1} Property" -f $sessionMatches.Count,$property)
                If ($sessionMatches.Count -eq 0) { Write-Warning ("No matches found using '{0}', refine the search criteria." -f $searchString) }
                ElseIf ($sessionMatches.Count -gt 10) { Write-Warning ("Too many matches found ({0}) using '{1}', refine the search criteria." -f $sessionMatches.Count,$searchString) }
                Else {
                    $Selection = "`n"
                    $Range = 1..($sessionMatches.Count)
                    For ($i = 0; $i -lt $sessionMatches.Count;$i++) {$Selection += (" [{0}] {1}`t{2}`t{3}`t{4}`n" -f ($i+1),$sessionMatches[$i].$property,$sessionMatches[$i].SessionHost,$sessionMatches[$i].SessionState,$sessionMatches[$i].Duration)}
                    $Selection += ("`n Please select a {0} or [Q] to Quit" -f $property)

                    Do { $Choice = Show-Menu -Title " Remove WVD User Session" -Menu $Selection -Style Mini -Color White -ClearScreen }
                    Until (($Range -contains $Choice) -OR ($Choice -eq "Q"))
                    If ($Choice -ne "Q") {
                        $Choice = $Choice - 1

                        Write-Output "`n" $sessionMatches[$Choice] | Format-Table -Autosize

                        $SessionHostStatus = Get-AzWvdSessionHost -HostPoolName $sessionMatches[$Choice].HostPool -ResourceGroupName $sessionMatches[$Choice].ResourceGroupName -Name $sessionMatches[$Choice].SessionHost | Select-Object -ExpandProperty Status
                        If ($SessionHostStatus -eq "Available") { 
                            Write-Warning ("Forcibly removing {0} Session Id {1} for {2} on {3}" -f $sessionMatches[$Choice].SessionState,$sessionMatches[$Choice].id,$sessionMatches[$Choice].UserPrincipalName,$sessionMatches[$Choice].SessionHost)
                            Remove-AzWvdUserSession -HostPoolName $sessionMatches[$Choice].HostPool -ResourceGroupName $sessionMatches[$Choice].ResourceGroupName -SessionHostName $sessionMatches[$Choice].SessionHost -Id $sessionMatches[$Choice].Id -Force -Confirm
                        }
                        Else { Write-Warning ("[{0}] Session Host Agent Status is: {1}, Session Host should be drained and rebooted" -f $sessionMatches[$Choice].SessionHost,$SessionHostStatus) }
                    }
                }
            }
                    
            $Done = Get-ChoicePrompt -Message "`nSearch for another User Session?" -OptionList "&Yes","&No"
        } Until ($Done -eq 1)
    }
}
