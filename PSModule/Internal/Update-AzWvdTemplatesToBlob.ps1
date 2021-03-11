Function Update-AzWvdTemplatesToBlob {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( {
            Param($CommandName, $ParameterName, $WordsToComplete, $CommandAst, $FakeBoundParameters)
            Get-AzSubscription | Where-Object { $_.Name -like "$WordsToComplete*" } | Select-Object -ExpandProperty Name
        })]
        [System.String]$SubscriptionName,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Storage/storageAccounts", "ResourceGroupName")]
        [System.String]$StorageAccountName
    )
    BEGIN {
        Connect-AzAccount -Identity -Subscription $SubscriptionName | Out-Null
        $stgContext = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName).Context
    }
    PROCESS {
        $AzureTemplateFiles = Get-ChildItem -Path (".\{0}\Deployment\LinkedTemplates" -f $env:BRANCH) -Filter *.json -File
        foreach ($AzureTemplate in $AzureTemplateFiles) {
            try { Set-AzStorageBlobContent -File $AzureTemplate -Container templates -Blob ("{0}/{1}" -f $env:BRANCH,$AzureTemplate.Name) -Context $stgContext -Force }
            catch { $PSCmdlet.ThrowTerminatingError($PSItem) }        
        }
    }
}