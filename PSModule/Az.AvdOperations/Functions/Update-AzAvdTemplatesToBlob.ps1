Function Update-AzAvdTemplatesToBlob {
    <#
        .SYNOPSIS
            Uploads Azure Virtual Desktop ARM templates to Blob Storage Account
        .DESCRIPTION
            This cmdlet takes a full directory path to the location of the support Azure Virtual Desktop ARM templates (Host Pool, Session Hosts, Configuration) and uploads them to the templates container in an Azure Storage Account.
    #>
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

        # Full path to the ARM template files (C:\MyStuff\LinkedTemplates)
        [Parameter(Mandatory=$true,HelpMessage="Full directory path to the Azure ARM Template(s)")]
        [System.String]$AzureTemplatePath,

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
        Write-Verbose ("[{0}] Collectiong Azure ARM Template(s) from: {1}" -f (Get-Date),$AzureTemplatePath)
        $AzureTemplateFiles = Get-ChildItem -Path $AzureTemplatePath -Filter *.json -File
        Write-Verbose ("[{0}] Found {1} files" -f (Get-Date),$AzureTemplateFiles.Count)
        foreach ($AzureTemplate in $AzureTemplateFiles) {
            #Write-Verbose ("[{0}] Working on {1}" -f (Get-date),$AzureTemplate)
            try { Set-AzStorageBlobContent -File $AzureTemplate.FullName -Container templates -Blob ("{0}/{1}" -f $GitBranch.ToLower(),$AzureTemplate.Name) -Context $stgContext -Force -Verbose:$false | Out-Null }
            catch { $PSCmdlet.ThrowTerminatingError($PSItem) }        
        }
    }
    END {
        If ($azContext) { $SCRIPT:AzAuthentication | Set-AzContext | Out-Null }
    }
}