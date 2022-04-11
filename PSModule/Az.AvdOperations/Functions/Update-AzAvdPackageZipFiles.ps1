Function Update-AzAvdPackageZipFiles {
    [CmdletBinding()]
    Param (
        $REMOTE_PATH,
        $BUILD
    )
    BEGIN {
        If (-NOT (Test-Path -Path "S:\AVD-Packages")) {
            Write-Error -Message "Missing required file path and directory" -Category InvalidOperation -Exception ([System.IO.DirectoryNotFoundException]::new()) -ErrorAction Stop
        }
    }
    PROCESS {
        If ($null -eq $REMOTE_PATH -OR $null -eq $BUILD) {
            Write-Verbose "One or more variables are empty, assuming script is called from GitHub Actions"
            Write-Host "Relying on GitHub Action Environment variables"
            If ($null -eq $env:REMOTE_PATH -OR $null -eq $env:BUILD) { Write-Error -Message "Environment Variables not found from GitHub Actions" -Category InvalidArgument -Exception ([System.ArgumentNullException]::new()) -ErrorAction Stop }
        }
        Else {
            Write-Verbose "Manual script execution, creating env parameters"
            Write-Host "Incoming parameters are not NULL, copying to environment variables"
            $env:REMOTE_PATH = $REMOTE_PATH
            $env:BUILD = $BUILD
        }
        # Creating variables
        $BUILD_PATH = ("{0}\{1}" -f $env:REMOTE_PATH, $env:BUILD)
        $BUILD_ZIP_FILE = ("S:\AVD-Packages\{0}\{1}_wvd_packages.zip" -f $env:BUILD.ToUpper(), $env:BUILD.ToLower())
        Write-Host ("AVD Build Path: {0}" -f $BUILD_PATH)
        Write-Host ("AVD Build Package Zip: {0}" -f $BUILD_ZIP_FILE)
        Write-Host ("Checking for backup {0} package ZIP files" -f $env:BUILD)
                
        $oldPackages = Get-ChildItem -Path ("S:\AVD-Packages\{0}" -f $env:BUILD.ToUpper()) -Filter "*bak*.zip" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-10) }
        If ($oldPackages) {
            Write-Host ("Found {0} old package ZIP files older than 10 days, these will be deleted!" -f $oldPackages.Count)
            $oldPackages | Remove-Item -Force
        }
        Else { Write-Host ("No old package ZIP files found older than 10 days") }

        Write-Host ("Checking for {0} wvd_packages.zip file..." -f $env:BUILD)
        If (Test-Path -Path $BUILD_ZIP_FILE) {
            Write-Host ("File found! Renaming file for backup and creating new compressed archive...")
            $backupName = $BUILD_ZIP_FILE.Replace("wvd_packages.zip",("wvd_packages_bak_{0}.zip" -f (Get-Date -Format "MMddyyyy_HHmmss")))
            Rename-Item -Path $BUILD_ZIP_FILE -NewName $backupName
        }
        Else { Write-Host ("File NOT FOUND - Creating new {0}_wvd_packages.zip..." -f $env:BUILD.ToLower()) }

        try {
            Write-Host ("Creating zip from {0} packages" -f $env:BUILD)
            Compress-Archive -Path ("{0}\Packages" -f $BUILD_PATH) -DestinationPath $BUILD_ZIP_FILE -CompressionLevel Optimal -Force
            
            $Result = Get-ChildItem -Path $BUILD_ZIP_FILE
            $Value = $Result.Length.ToString().Length
            If ($Value -le 6) { $fileSize = ("{0:N2} KB" -f ($Result.Length / 1KB)) }
            ElseIf ($Value -le 9 -AND $Value -gt 6) { $fileSize = ("{0:N2} MB" -f ($Result.Length / 1MB)) }
            ElseIf ($Value -ge 10) { $fileSize = ("{0:N2} GB" -f ($Result.Length / 1GB)) }

            Write-Host ("{0} WVD Package Zip ({1}) Created at: {2}" -f $env:BUILD, $fileSize, $Result.CreationTime)
        }
        catch {
            Write-Warning ("Process failed to successfully create the {0}_wvd_package.zip file" -f $env:BUILD.ToLower())
            Write-Warning $PSItem.Exception.Message
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }
}