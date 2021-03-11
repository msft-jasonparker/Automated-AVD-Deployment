Function New-AzWvdDscCompilationJob {
    [CmdletBinding()]
    Param (
        # Name of the Resource Group of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true,ParameterSetName="Default")]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$AutomationResourceGroup,

        # Name of the WVD Artifact Blob Storage Account (supports tab completion)
        [Parameter(Mandatory=$true,ParameterSetName="Default")]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Automation/automationAccounts","AutomationResourceGroup")]
        [System.String]$AutomationAccountName,

        # Name of the Resource Group of the WVD Host Pool (supports tab completion)
        [Parameter(Mandatory=$true,ParameterSetName="Default")]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$HostPoolResourceGroup,

        # Name of the WVD Artifact Blob Storage Account (supports tab completion)
        [Parameter(Mandatory=$true,ParameterSetName="Default")]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.DesktopVirtualization/hostPools","HostPoolResourceGroup")]
        [System.String]$HostPoolName

    )
    BEGIN {
        #Requires -Modules @{ ModuleName = "Az.DesktopVirtualization"; ModuleVersion = "2.0.0" }
        Write-Verbose ("Selecting DSC Configuration Data file")
        Do {
            Show-Menu -Title "Select DSC Configuration Data file (*.psd1)" -Style Info -Color Cyan -DisplayOnly
            $dscConfigurationData = Get-FileNameDialog -InitialDirectory (Get-Location).Path -Filter "PowerShell Data files (*.psd1)| *.psd1"
            Write-Verbose "`t $dscConfigurationData"
            If ([system.string]::IsNullOrEmpty($dscConfigurationData)) { Write-Warning ("No Configuration Data file selected!") }
            Else { $ValidFile = $true }
        } Until ($ValidFile -eq $true)

        $expirationTime = (Get-Date).AddHours(24)
    }
    PROCESS {
        Write-Verbose ("Importing PowerShell Data File")
        $configurationData = Import-PowerShellDataFile $dscConfigurationData

        Write-Verbose ("Gathering Host Pool Specific Data")
        $hostPoolInfo = Get-AzWvdHostPool -ResourceGroupName $HostPoolResourceGroup -HostPoolName $HostPoolName

        Write-Verbose ("Generating Node Specific Configuration")
        $nodeData = @{
            NodeName                = $HostPoolName
            Role                    = $hostPoolInfo.Tag["WVD-Build"]
            WvdArtifactLocation     = $hostPoolInfo.Tag["WVD-ArtifactLocation"]
            RegistrationToken       = (Update-AzWvdHostPool -ResourceGroupName $HostPoolResourceGroup -HostPoolName $HostPoolName -RegistrationInfoExpirationTime $expirationTime -RegistrationInfoRegistrationTokenOperation Update).RegistrationInfoToken
            WvdFsLogixVhdLocation   = $hostPoolInfo.Tag["WVD-FsLogixVhdLocation"]
        }

        $configurationData.AllNodes += $nodeData
        $configurationData.WvdData.WvdAgentInstallUri = Get-LatestWVDConfigZip -OutputType Local -LocalPath $hostPoolInfo.Tag["WVD-ArtifactLocation"]

        Write-Verbose ("Creating new / updated DSC Compilation - {0}.{1}" -f $hostPoolInfo.Tag["WVD-DscConfiguration"],$HostPoolName)
        Start-AzAutomationDscCompilationJob -ResourceGroupName $AutomationResourceGroup -AutomationAccountName $AutomationAccountName -ConfigurationName $hostPoolInfo.Tag["WVD-DscConfiguration"] -ConfigurationData $configurationData -WhatIf
    }
}