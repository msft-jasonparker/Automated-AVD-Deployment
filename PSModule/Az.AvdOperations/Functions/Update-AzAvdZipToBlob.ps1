Function Update-AzAvdZipToBlob {
    [CmdletBinding()]
    Param(
        $ResourceGroupName,
        $StorageAccountName,
        $Container,
        $BUILD
    )
    BEGIN {
        Get-AzAuthentication
        Write-Verbose ("[Azure Authentication] {0} Connected to {1} ({2})" -f $SCRIPT:AzAuthentication.Account.Id,$SCRIPT:AzAuthentication.Subscription.Name,$SCRIPT:AzAuthentication.Subscription.Id)
        If (-NOT (Test-Path -Path "S:\AVD-Packages")) {
            Write-Error -Message "Missing required file path and directory" -Category InvalidOperation -Exception ([System.IO.DirectoryNotFoundException]::new()) -ErrorAction Stop
        }
    }
    PROCESS {
        If ($null -eq $BUILD) {
            Write-Verbose "One or more variables are empty, assuming script is called from GitHub Actions"
            Write-Host "Relying on GitHub Action Environment variables"
            If ($null -eq $env:BUILD) { Write-Error -Message "Environment Variables not found from GitHub Actions" -Category InvalidArgument -Exception ([System.ArgumentNullException]::new()) -ErrorAction Stop }
        }
        Else {
            Write-Verbose "Manual script execution, creating env parameters"
            Write-Host "Incoming parameters are not NULL, copying to environment variables"
            $env:BUILD = $BUILD
        }
        $stgContext = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName).Context
        $AzureZipFile = Get-ChildItem -Path ("S:\AVD-Packages\{0}\{0}_wvd_packages.zip" -f $env:BUILD.ToLower()) -File
        try { Set-AzStorageBlobContent -File $AzureZipFile -Container $Container -Blob ("{0}/{1}" -f $env:BRANCH.toLower(),$AzureZipFile.Name) -Context $stgContext -Force }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
    }
}