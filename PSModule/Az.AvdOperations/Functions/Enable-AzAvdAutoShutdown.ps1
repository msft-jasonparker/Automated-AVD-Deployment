Function Enable-AzAvdAutoShutdown {
    <#
        .SYNOPSIS
            Enables Virtual Machine AutoShutdown
        .DESCRIPTION
            This cmdlet requires an Azure ARM Template, which should be stored in a Storage Account container called 'templates'. When run, a query of Host Pools will be performed and allow the operator to select which Host Pool (Personal types ONLY) to enable for autoshutodwn. Only virtual machines which have been assigned to a user will be processes as the users UPN is used as the notification mechanism.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        # Resource Group name for the Storage Account (supports tab completion - in the same subscription)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$StorageAccountResourceGroup,

        # Storage Account name where the ARM template is stored (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Storage/storageAccounts","StorageAccountResourceGroup")]
        [System.String]$StorageAccountName,
        
        # Time to shutdown the Virtual Machine (24hr EST ONLY - 16:00 = 4PM EST)
        [Parameter(Mandatory=$true)]
        [System.String]$ShutdownTime,

        # Time in minutes to send notification before shutdown event (Maximum value: 120)
        [Parameter(Mandatory=$true)]
        [ValidateRange(1,120)]
        [Int32]$NotificationTime
    )
    BEGIN {
        #Requires -Module Az.DesktopVirtualization
        Get-AzAuthentication
        Write-Verbose ("[Azure Authentication] {0} Connected to {1} ({2})" -f $SCRIPT:AzAuthentication.Account.Id,$SCRIPT:AzAuthentication.Subscription.Name,$SCRIPT:AzAuthentication.Subscription.Id)

        Do {
            $GitBranch = Show-Menu -Title "GitHub Branch Selection" -Menu ("`nPlease provide the name of the branch you want to deploy from GitHub") -Style Info -Color Cyan
            $Done = Get-ChoicePrompt -Title "GitHub Branch" -Message ("Is ['{0}'] the correct branch?" -f $GitBranch.ToLower()) -OptionList "&Yes","&No" -Default 1
        } Until ($Done -eq 0)
    }
    PROCESS {
        [System.Collections.Generic.List[Object]]$deploymentJobs = @()
        Write-Host ("[{0}] Setting up inital variables..." -f (Get-Date))
        $expirationTime = (Get-Date).AddHours(24)
        $deploymentString = ([Guid]::NewGuid()).Guid.Split("-")[-1]    

        Write-Host ("[{0}] Generating Storage SAS Tokens and fetching various URL(s)..." -f (Get-Date))
        $stgAccountContext = (Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroup).Context

        $ShutdownTemplateUri = New-AzStorageBlobSASToken -Container templates -Blob ("{0}/Deploy-WVD-AutoShutdown.json" -f $GitBranch.ToLower()) -Protocol HttpsOnly -Permission r -StartTime (Get-Date) -ExpiryTime $expirationTime -Context $stgAccountContext -FullUri
               
        Do {
            Write-Verbose "Getting WVD Host Pools (Personal ONLY)..."
            $HPs = Get-AzWvdHostPool -Verbose:$false -Debug:$false | Where-Object {$_.HostPoolType -eq "Personal"} | Select-Object @{l="Name";e={$_.Name.Split("/")[-1]}},@{l="ResourceGroupName";e={$_.Id.Split("/")[4]}},Tag,VMTemplate
            
            If ($null -eq $HPs) {
                Show-Menu -Title ("No matching Host Pools found, auto-shutdown is only available for 'Personal' Host Pools") -Style Info -Color Magenta -DisplayOnly
                Exit
            }

            Write-Verbose ("Found {0} Azure WVD Host Pools" -f $HPs.Count)
            $HPSelection = ""
            $HPRange = 1..($HPs.Count)
            For ($i = 0; $i -lt $HPs.Count;$i++) {$HPSelection += (" [{0}] {1}`n" -f ($i+1),$HPs[$i].Name)}
            $HPSelection += "`n Please select a Host Pool or [Q] to Quit"

            Do {
                If ($HPChoice -eq "Q") { Return }
                Start-Sleep -Milliseconds 1999
                $HPChoice = Show-Menu -Title "Select an Azure WVD Host Pool" -Menu $HPSelection -Style Full -Color White -ClearScreen
            }
            While (($HPRange -notcontains $HPChoice) -OR (-NOT $HPChoice.GetType().Name -eq "Int32"))
            $HPChoice = $HPChoice - 1
            
            Clear-Host
            Write-Host ("[{0}] Host Pool: {1}" -f (Get-Date),$HPs[$HPChoice].Name)
            Write-Host ("[{0}] Host Pool: {1} | Gathering Session Hosts and Assigned Users" -f (Get-Date),$HPs[$HPChoice].Name)

            $deploymentName = ("Deploy-WVD-AutoShutdown-Schedule-{0}" -f $deploymentString)
            $hostPoolObjects = @{
                sessionHosts = [System.Collections.Generic.List[Object]]@()
            }

            $sessionHostInfo = Get-AzWvdSessionHost -ResourceGroupName $HPs[$HPChoice].ResourceGroupName -HostPoolName $HPs[$HPChoice].Name | Where-Object { $null -ne $_.AssignedUser }
            Foreach ($sessionHost in $sessionHostInfo) {
                $sessionHostProperties = @{
                    vmName = $sessionHost.ResourceId.split("/")[-1]
                    assignedUser = $sessionHost.AssignedUser
                    resourceID = $sessionHost.ResourceId
                }

                $hostPoolObjects.sessionHosts.Add($sessionHostProperties)
            }
        
            $templateParams = [Ordered]@{
                Name = $deploymentName
                hostPoolObjects = $hostPoolObjects
                shutdownTime = $ShutdownTime
                notificationTime = $NotificationTime
                ResourceGroupName = $HPs[$HPChoice].ResourceGroupName
                TemplateUri = $ShutdownTemplateUri
            }

            If ($PSCmdlet.ShouldProcess($HPs[$HPChoice].Name,"Initiate AutoShutdown Deployment")) {
                $deploymentJob = New-AzResourceGroupDeployment @templateParams -AsJob
                If ($deploymentJob) {
                    $deploymentJobs.Add($HPs[$HPChoice])
                    Write-Host ("Active Deployment Jobs: {0}" -f (Get-Job -State Running).Count)
                    try {
                        While ($true) {
                            If (Get-AzResourceGroupDeployment -ResourceGroupName $HPs[$HPChoice].ResourceGroupName -Name $deploymentName -ErrorAction SilentlyContinue) { Break }
                            Else {
                                Write-Verbose ("[{0}] Waiting for job: {1}" -f (Get-Date),$deploymentName)
                                Start-Sleep -Seconds 5
                            }
                        }
                    }
                    catch {
                        Write-Warning ("WVD Auto-Shutdown Deployment encountered a problem")
                        Return
                    }
                }
                Else {
                    Write-Warning ("WVD DSC Configuration Deployment failed to start")
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
                $deploymentResults = Get-AzResourceGroupDeployment -ResourceGroupName $HostPool.resourceGroupName -Name ("Deploy-WVD-AutoShutdown-Schedule-{0}" -f $deploymentString) -ErrorAction SilentlyContinue
                If ($deploymentResults) {
                    If ($deploymentResults.ProvisioningState -eq "Running") {$i++}
                    $elapsedTime = $deploymentResults.TimeStamp.ToUniversalTime() - $currentTime
                    $obj = [PSCustomObject][Ordered]@{
                        Name = ("Deploy-WVD-AutoShutdown-Schedule-{0}  " -f $deploymentString)
                        ResourceGroup = ("{0}  " -f $HostPool.resourceGroupName)
                        Status = ("{0}  " -f $deploymentResults.ProvisioningState)
                        Duration = ("{0:N0}.{1:N0}:{2:N0}:{3:N0}" -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds)
                    }
                    $Jobs.Add($obj)
                }
                Else {
                    $i++
                    $obj = [PSCustomObject][Ordered]@{
                        Name = ("Deploy-WVD-AutoShutdown-Schedule-{0}  " -f $deploymentString)
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
                Write-Host "2" -ForegroundColor Magenta -NoNewline
                Write-Host " Seconds`r`n"
            }
            If ($stopWatch.Elapsed.TotalMinutes -gt 89) { Write-Warning ("One or More of the Deployment Jobs has exceeded 90 minutes deployment time!")}
        } Until ($i -eq 0)
        Write-Host "Done!`n`r"
    }
}