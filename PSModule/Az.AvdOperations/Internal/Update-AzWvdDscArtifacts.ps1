Function Update-AzWvdDscArtifacts {
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
        #Requires -Modules Az.Compute,Az.Accounts
        
        Write-Verbose ("[{0}] Checking to Azure Context" -f (Get-Date))
        $azContext = Get-AzContext
        If ($azContext) {
            Write-Verbose ("`tConnected to: {0}, using {1}" -f $azContext.Subscription.Name, $azContext.Account.Id)
            If (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue) { Write-Verbose ("`tStorage Account Found: {0} in {1}" -f $StorageAccountName, $ResourceGroupName) }
            Else {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.SystemException]::new(("Storage Account Not Found in {0} of the {1} subscription" -f $ResourceGroupName, $azContext.Subscription.Name)),
                        "StgAcctNotFound",
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        "Storage Account Not Found"
                    )
                )
            }
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
            $Files = Get-ChildItem -Path $Path -Filter *.ps1 -File
            If ($Files.Count -gt 0) { Write-Verbose ("[{0}] Path provided found {1} DSC configuration files" -f (Get-Date), $Files.Count) }
            Else {
                Write-Warning ("Unable to find files using the following command: Get-ChildItem -Path {0} -Filter *.ps1 -File" -f $Path)
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
            try { Publish-AzVMDscConfiguration -ConfigurationPath $File.FullName -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ContainerName $Container -Force }
            catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
        }
    }
}