Function Update-AzWvdDscToBlob {
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
        $DscConfigurationFiles = Get-ChildItem -Path (".\{0}\Deployment\DscConfigurations" -f $env:BRANCH) -Filter *.ps1 -File
        foreach ($DscConfiguration in $DscConfigurationFiles) {
            If (-NOT (Test-Path -Path (".\{0}\Deployment\DscConfigurations\ZipFiles" -f $env:BRANCH))) { New-Item -Path (".\{0}\Deployment\DscConfigurations\ZipFiles" -f $env:BRANCH) -ItemType Directory }
            $DscArchive = (".\{0}\Deployment\DscConfigurations\ZipFiles\{1}.zip" -f $env:BRANCH,$DscConfiguration.Name)
            try {
                Publish-AzVMDscConfiguration -ConfigurationPath $DscConfiguration.FullName -OutputArchivePath $DscArchive -Force
                Set-AzStorageBlobContent -File $DscArchive -Container dsc -Blob ("{0}/{1}" -f $env:BRANCH,$DscArchive.Split("\")[-1]) -Context $stgContext -Force
            }
            catch { $PSCmdlet.ThrowTerminatingError($PSItem) }        
        }
    }
}