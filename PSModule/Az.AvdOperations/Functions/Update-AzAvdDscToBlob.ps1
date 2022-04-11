Function Update-AzAvdDscToBlob {
    <#
        .SYNOPSIS
            Uploads Desired State Configuration PS1 scripts to an Azure Storage Account as a compressed archive.
        .DESCRIPTION
            This cmdlet takes a full directory path to the location of a Desired State Configuration script and will Publish the VM Configuration as a Zip file and then upload it to a specified Storage Account.
    #>
    [CmdletBinding()]
    Param(
        # Name of the Azure Subscription where the Storage Account is located. (supports tab completion)
        [Parameter(Mandatory=$true)]
        [ArgumentCompleter({
            Param($CommandName,$ParameterName,$WordsToComplete,$CommandAst,$FakeBoundParameters)
            Get-AzSubscription | Where-Object {$_.Name -like "$WordsToComplete*"} | Select-Object -ExpandProperty Name
        })]
        [System.String]$StorageAccountSubscription,

        # Name of the Resource Group where the Storage Account is located. (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$StorageAccountResourceGroup,

        # Name of the Storage Account (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Storage/storageAccounts","StorageAccountResourceGroup")]
        [System.String]$StorageAccountName,

        # Full path to the DSC configuration script (C:\MyStuff\DscConfigurations)
        [Parameter(Mandatory=$true,HelpMessage="Full directory path to the DSC Configuration Script(s)")]
        [System.String]$DscConfigurationPath,

        # Use this switch when calling the cmdlet from GitHub Self-Hosted Runners
        [Parameter(Mandatory=$false)]
        [Switch]$SelfHostedRunner
    )
    BEGIN {
        Show-Menu -Title $PSCmdlet.MyInvocation.MyCommand.Name -Style Info -Color White -DisplayOnly
        Get-AzAuthentication
        Write-Verbose ("[Azure Authentication] {0} Connected to {1} ({2})" -f $SCRIPT:AzAuthentication.Account.Id,$SCRIPT:AzAuthentication.Subscription.Name,$SCRIPT:AzAuthentication.Subscription.Id)
        If ($SCRIPT:AzAuthentication.Subscription.Name -ne $StorageAccountSubscription) {
            $azContext = Connect-AzAccount -Subscription $StorageAccountSubscription | Out-Null
            Write-Host ("`tConnecting to: {0}, using {1}" -f $azContext.Subscription.Name,$azContext.Account.Id)
        }

        If ($SelfHostedRunner) {
            If ($azContext.Account.Type -eq "ManagedService" -OR $SCRIPT:AzAuthentication.Account.Type -eq "ManagedService") { $GitBranch = $env:BRANCH }
            Else {
                Write-Warning ("NOT EXECUTED FROM GITHUB ACTION RUNNER, ABORTING THE OPERATION!")
                Exit
            }
        }
        Else {
            Do {
                $GitBranch = Show-Menu -Title "GitHub Branch Selection" -Menu ("`nPlease provide the name of the GitHub branch you are working from") -Style Info -Color Cyan
                $Done = Get-ChoicePrompt -Title "GitHub Branch" -Message ("Is ['{0}'] the correct branch?" -f $GitBranch.ToLower()) -OptionList "&Yes","&No" -Default 1
            } Until ($Done -eq 0)
        }
        
        Write-Verbose ("[{0}] Creating Storage Account Context..." -f (Get-Date))
        $stgContext = (Get-AzStorageAccount -ResourceGroupName $StorageAccountResourceGroup -StorageAccountName $StorageAccountName).Context
    }
    PROCESS {
        Write-Verbose ("[{0}] Collectiong DSC Configuration Script(s) from: {1}" -f (Get-Date),$DscConfigurationPath)
        $DscConfigurationFiles = Get-ChildItem -Path $DscConfigurationPath -Filter *.ps1 -File
        Write-Verbose ("[{0}] Found {1} files" -f (Get-Date),$DscConfigurationFiles.Count)
        foreach ($DscConfiguration in $DscConfigurationFiles) {
            Write-Verbose ("[{0}] Checking / creating directory for DSC Configuration Script archive file" -f (Get-Date))
            If (-NOT (Test-Path -Path ("{0}\ZipFiles" -f $DscConfigurationPath))) { New-Item -Path ("{0}\ZipFiles" -f $DscConfigurationPath) -ItemType Directory | Out-Null }
            $DscArchive = ("{0}\ZipFiles\{1}.zip" -f $DscConfigurationPath,$DscConfiguration.Name)
            try {
                Write-Verbose ("[{0}] Creating DSC Configuration Script archive" -f (Get-Date))
                Publish-AzVMDscConfiguration -ConfigurationPath $DscConfiguration.FullName -OutputArchivePath $DscArchive -Force -Verbose:$false | Out-Null
                Write-Verbose ("[{0}] Uploading DSC Configuration Script archive to Storage Account container" -f (Get-Date))
                Set-AzStorageBlobContent -File $DscArchive -Container dsc -Blob ("{0}/{1}" -f $GitBranch.ToLower(),$DscArchive.Split("\")[-1]) -Context $stgContext -Force -Verbose:$false | Out-Null
            }
            catch { $PSCmdlet.ThrowTerminatingError($PSItem) }        
        }
    }
    END {
        If ($azContext) { $SCRIPT:AzAuthentication | Set-AzContext | Out-Null }
    }
}