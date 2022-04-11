Function Update-AzWvdTemplateArtifacts {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute("Microsoft.Storage/storageAccounts", "ResourceGroupName")]
        [System.String]$StorageAccountName,

        [Parameter(Mandatory = $true)]
        [System.String]$Container,

        [Parameter(Mandatory = $true)]
        [System.String]$Path
    )
    BEGIN {
        #Requires -Modules Az.Storage,Az.Accounts
        
        Write-Verbose ("[{0}] Checking to Azure Context" -f (Get-Date))
        $azContext = Get-AzContext
        If ($azContext) {
            Write-Verbose ("`tConnected to: {0}, using {1}" -f $azContext.Subscription.Name, $azContext.Account.Id)
            try { $stgContext = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ErrorAction Stop).Context }
            catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
        }
        Else {    
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.SystemException]::new("Unable to validate Azure Context, try running Connect-AzAccount before running this command"),
                    "AzContextNotFound",
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    "Unable to validate Azure Context"
                )
            )
        }

        If (Test-Path -Path $Path) {
            Write-Verbose ("[{0}] The provided path ({1}) is valid" -f (Get-Date), $Path)
            $Files = Get-ChildItem -Path $Path -Filter *.json -File
            If ($Files.Count -gt 0) { Write-Verbose ("[{0}] Path provided found {1} ARM JSON template files" -f (Get-Date), $Files.Count) }
            Else {
                Write-Warning ("Unable to find files using the following command: Get-ChildItem -Path {0} -Filter *.json -File" -f $Path)
                Return
            }
        }
        Else {
            Write-Warning ("Path not found: {0}" -f $Path)
            Return
        }
    }
    PROCESS {
        Foreach ($File in $Files) {
            try { Set-AzStorageBlobContent -File $File.FullName -Container $Container -Blob $File.Name -Context $stgContext -Force -ErrorAction Stop }
            catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
        }
    }
}