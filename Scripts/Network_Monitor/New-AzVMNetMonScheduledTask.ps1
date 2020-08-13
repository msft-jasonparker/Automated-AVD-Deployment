[CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
Param (
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
    [System.String]$ResourceGroupName,
    [Parameter(Mandatory=$true)]
    [System.String]$LocalPath,
    [Parameter(Mandatory=$true)]
    [System.String]$domainSuffix
)
    BEGIN {

        Function Update-AzContext {
            [CmdletBinding()]
            Param()
        
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
                    $menuPrompt = "/" * (95)
                    $menuPrompt += "`n`r////`n`r//// $Title`n`r////`n`r"
                    $menuPrompt += "/" * (95)
                    $menuPrompt += "`n`n"
                }
                ElseIf ($Style -eq "Mini") {
                    #$menuPrompt = "`n"
                    $menuPrompt = "\" * (80)
                    $menuPrompt += "`n\\\\  $Title`n"
                    $menuPrompt += "\" * (80)
                    $menuPrompt += "`n"
                }
                ElseIf ($Style -eq "Info") {
                    #$menuPrompt = "`n"
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
        
            Write-Verbose "Getting Azure Subscriptions..."
            $Subs = Get-AzSubscription -Verbose:$false -Debug:$false | ForEach-Object {$_.Name} | Sort-Object
            Write-Verbose ("Found {0} Azure Subscriptions" -f $Subs.Count)
            $SubSelection = (@"
`n
"@)
            $SubRange = 0..($Subs.Count - 1)
            For ($i = 0; $i -lt $Subs.Count;$i++) {$SubSelection += " [$i] $($Subs[$i])`n"}
            $SubSelection += "`n Please select a Subscription"
        
            Do {$SubChoice = Show-Menu -Title "Select an Azure Subscription" -Menu $SubSelection -Style Full -Color White -ClearScreen}
            While (($SubRange -notcontains $SubChoice) -OR (-NOT $SubChoice.GetType().Name -eq "Int32"))
            
            Write-Verbose ("Updating Azure Subscription to: {0}" -f $Subs[$SubChoice])
            Select-AzSubscription -Subscription $Subs[$SubChoice] -Verbose:$false -Debug:$false | Out-Null
            Clear-Host
        }

        try {
            If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Write-Verbose ("This script requires an 'Administrator: Windows PowerShell' session")
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::New(
                        [System.SystemException]::New("PowerShell session not run as Administrator"),
                        "InvalidPowerShellSession",
                        [System.Management.Automation.ErrorCategory]::InvalidResult,
                        "Requires Elevation"
                    )
                )                
            }
            Else {
                # Checks for legacy Azure RM PowerShell Module
                If ((Get-Command Get-AzureRMContext -ErrorAction SilentlyContinue)) {
                    Write-Verbose ("AzureRM Module installed, this script requires Az Module from PSGallery")
                    $PSCmdlet.ThrowTerminatingError(
                        [System.Management.Automation.ErrorRecord]::New(
                            [System.SystemException]::New("Invalid Azure Powershell module installed (AzureRM)"),
                            "InvalidPowerShellModule",
                            [System.Management.Automation.ErrorCategory]::InvalidResult,
                            "AzureRm Module"
                        )
                    )
                }
                # Checks for current Azure PowerShell Module
                ElseIf (-NOT (Get-Command Get-AzContext -ErrorAction SilentlyContinue)) {
                    Write-Verbose ("Missing valid Azure PowerShell Module - Please install Az Module from PSGallery")
                    $PSCmdlet.ThrowTerminatingError(
                        [System.Management.Automation.ErrorRecord]::New(
                            [System.SystemException]::New("Missing valid Azure Powershell module (Az)"),
                            "InvalidPowerShellModule",
                            [System.Management.Automation.ErrorCategory]::InvalidResult,
                            "Az Module"
                        )
                    )
                }
                Else {
                    Write-Verbose ("Azure Powershell Module verified")
                    If (Get-AzContext) { Update-AzContext }
                    Else {
                        Write-Verbose ("Missing Azure login context, please run Connect-AzAccount before running this script.")
                        $PSCmdlet.ThrowTerminatingError(
                            [System.Management.Automation.ErrorRecord]::New(
                                [System.SystemException]::New("Missing Azure Login Context"),
                                "MissingAzContext",
                                [System.Management.Automation.ErrorCategory]::InvalidResult,
                                "Missing Azure Login Context"
                            )
                        )
                    }
                }
            }
        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
    }
    PROCESS {
        Write-Verbose ("Collecting Virtual Machines from: {0}" -f $ResourceGroupName)
        Get-AzVM -ResourceGroupName $ResourceGroupName -Status | Where-Object {$_.PowerState -eq "vm running"} | Select-Object Name | Export-Csv ("{0}\{1}_VMs.csv" -f $env:TEMP,$ResourceGroupName) -NoTypeInformation -Force
        $virtualMachines = Import-Csv ("{0}\{1}_VMs.csv" -f $env:TEMP,$ResourceGroupName)
        Write-Verbose ("Found {0:N0} Virtual Machines in {1}" -f $virtualMachines.Count,$ResourceGroupName)

        If ($PSCmdlet.ShouldProcess(("{0}, VMs: {1:N0}" -f $ResourceGroupName,$virtualMachines.Count),("Create Network Monitor Scheduled Task"))) {        
            $i = 0
            ForEach ($vm in $virtualMachines) {
                
                $Progress = @{
                    Activity = "Setting up Network Monitor Remote Capture Task"
                    Status = ("Processing VM: {0} ({1:N0} of {2:N0})" -f $vm.Name,($i + 1),$virtualMachines.Count)
                    PercentComplete = (($i/$virtualMachines.count)*100)
                }
            
                Write-Progress @Progress
                If (!(Test-Path -Path ("\\{0}.{1}\admin$\Utilities\NetMon" -f $vm.Name,$domainSuffix))) {
                    $msg = ("Creating directory on remote computer")
                    Write-Progress @Progress -CurrentOperation $msg
                    New-Item -Path ("\\{0}.{1}\admin$\Utilities\NetMon" -f $vm.Name,$domainSuffix) -ItemType Directory | Out-Null
            
                    $msg = ("Copying files (XML and PS1) to remote computer")
                    Write-Progress @Progress -CurrentOperation $msg
                    Copy-Item -Path ("{0}\NetMon*" -f $LocalPath) -Destination ("\\{0}.{1}\admin$\Utilities" -f $vm.Name,$domainSuffix) -Force -ErrorAction SilentlyContinue
                                        
                    $SchTaskCapture = Invoke-Command -ComputerName ("{0}.{1}" -f $vm.Name,$domainSuffix) -ScriptBlock { & SchTasks.exe /QUERY /TN '\Microsoft\Windows\NetTrace\NetMonCaptures' /FO CSV } -ErrorAction SilentlyContinue | ConvertFrom-Csv
                    If (!$SchTaskCapture) {
                        $msg = ("Creating NetMon Capture Scheduled Task on remote computer")
                        Write-Progress @Progress -CurrentOperation $msg
                        Invoke-Command -ComputerName ("{0}.{1}" -f $vm.Name,$domainSuffix) -ScriptBlock { & SchTasks.exe /CREATE /TN '\Microsoft\Windows\NetTrace\NetMonCaptures' /XML C:\Windows\Utilities\NetMonCapture.xml } | Out-Null
                    }
                    Else {
                        Write-Warning ("[{0}]`tNetMonCapture Scheduled Task already exists" -f $vm.Name)
                    }

                    $SchTaskCleanUp = Invoke-Command -ComputerName ("{0}.{1}" -f $vm.Name,$domainSuffix) -ScriptBlock { & SchTasks.exe /QUERY /TN '\Microsoft\Windows\NetTrace\NetMonCleanUp' /FO CSV} -ErrorAction SilentlyContinue | ConvertFrom-Csv
                    If (!$SchTaskCleanUp) {
                        $msg = ("Creating NetMon Clean Up Scheduled Task on remote computer")
                        Write-Progress @Progress -CurrentOperation $msg
                        Invoke-Command -ComputerName ("{0}.{1}" -f $vm.Name,$domainSuffix) -ScriptBlock { & SchTasks.exe /CREATE /TN '\Microsoft\Windows\NetTrace\NetMonCleanUp' /XML C:\Windows\Utilities\NetMonCleanUp.xml } | Out-Null
                    }
                    Else {
                        Write-Warning ("[{0}]`tNetMonCleanUp Scheduled Task already exists" -f $vm.Name)
                    }
                }
                Else {
                    $msg = ("Copying files (XML and PS1) to remote computer")
                    Write-Progress @Progress -CurrentOperation $msg
                    Copy-Item -Path ("{0}\NetMon*" -f $LocalPath) -Destination ("\\{0}.{1}\admin$\Utilities" -f $vm.Name,$domainSuffix) -Force -ErrorAction SilentlyContinue
                    
                    $SchTaskCapture = Invoke-Command -ComputerName ("{0}.{1}" -f $vm.Name,$domainSuffix) -ScriptBlock { & SchTasks.exe /QUERY /TN '\Microsoft\Windows\NetTrace\NetMonCaptures' /FO CSV } -ErrorAction SilentlyContinue | ConvertFrom-Csv
                    If (!$SchTaskCapture) {
                        $msg = ("Creating NetMon Capture Scheduled Task on remote computer")
                        Write-Progress @Progress -CurrentOperation $msg
                        Invoke-Command -ComputerName ("{0}.{1}" -f $vm.Name,$domainSuffix) -ScriptBlock { & SchTasks.exe /CREATE /TN '\Microsoft\Windows\NetTrace\NetMonCaptures' /XML C:\Windows\Utilities\NetMonCapture.xml } | Out-Null
                    }
                    Else {
                        Write-Warning ("[{0}]`tNetMonCapture Scheduled Task already exists" -f $vm.Name)
                    }

                    $SchTaskCleanUp = Invoke-Command -ComputerName ("{0}.{1}" -f $vm.Name,$domainSuffix) -ScriptBlock { & SchTasks.exe /QUERY /TN '\Microsoft\Windows\NetTrace\NetMonCleanUp' /FO CSV } -ErrorAction SilentlyContinue | ConvertFrom-Csv
                    If (!$SchTaskCleanUp) {
                        $msg = ("Creating NetMon Clean Up Scheduled Task on remote computer")
                        Write-Progress @Progress -CurrentOperation $msg
                        Invoke-Command -ComputerName ("{0}.{1}" -f $vm.Name,$domainSuffix) -ScriptBlock { & SchTasks.exe /CREATE /TN '\Microsoft\Windows\NetTrace\NetMonCleanUp' /XML C:\Windows\Utilities\NetMonCleanUp.xml } | Out-Null
                    }
                    Else {
                        Write-Warning ("[{0}]`tNetMonCleanUp Scheduled Task already exists" -f $vm.Name)
                    }
                }
                $i++
            }
        }
    }