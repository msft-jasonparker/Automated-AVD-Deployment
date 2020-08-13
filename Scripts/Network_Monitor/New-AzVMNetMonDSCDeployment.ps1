[CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
Param (
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
    [System.String]$ResourceGroupName,
    [Parameter(Mandatory=$true)]
    [System.String]$DscConfigUri,
    [Parameter(Mandatory=$true)]
    [System.String]$TemplateFilePath
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
            $Subs = Get-AzSubscription -Verbose:$false -Debug:$false | % {$_.Name} | Sort-Object
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

        If ($PSCmdlet.ShouldProcess(("{0}, VMs: {1:N0}" -f $ResourceGroupName,$virtualMachines.Count),("Deploy Network Monitor ARM Template"))) {
            try { New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile ("{0}\WindowsNetMon.json" -f $TemplateFilePath) -vmArray $virtualMachines.Name -moduleZipUri $DscConfigUri }
            catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
        }
    }