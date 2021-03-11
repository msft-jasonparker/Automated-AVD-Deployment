Function Update-AzWvdPackageZipFiles {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [System.String]$Path,

        [Parameter(Mandatory = $true)]
        [System.String]$Build
    )
    BEGIN {
        If (Test-Path -Path ("{0}\{1}" -f $Path, $Build)) {
            $Files = Get-ChildItem -Path ("{0}\{1}" -f $Path, $Build) -Filter *.zip -File
            If ($Files.Count -gt 0) { Write-Verbose ("Path validated and found existing files") }
            Else { Write-Verbose ("Path validated, no files exist") }
        }
        Else {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.SystemException]::new("Provided Path does not exist, verify the Path before running this command."),
                    "PathNotFound",
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    "Path Not Found"
                )
            )
        }
    }
    PROCESS {
        Write-Host ("Checking for backup {0} package ZIP files" -f $Build)
                
        $oldPackages = Get-ChildItem -Path ("{0}\{1}_wvd_packages_bak_*.zip" -f $Path, $Build) -File
        If ($oldPackages | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-10) }) {
            Write-Host ("Found {0} backup package ZIP files last modified more than 10 days ago, removing older files" -f $oldPackages.Count)
            $oldPackages | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-10) } | Remove-Item -Force
        }
        ElseIf ($oldPackages.Count -gt 3) {
            Write-Host ("Found {0} backup package ZIP files, removing {1} older files by modified date" -f $oldPackages.Count, ($oldPackages.Count - 3))
            $oldPackages | Sort-Object LastWriteTime | Select-Object -First ($oldPackages.Count - 3) | Remove-Item -Force 
        }
        Else { Write-Host ("No backup package ZIP files found to clean up") }

        Write-Host ("Checking for {0} wvd_packages.zip file..." -f $Build)
        If (Test-Path -Path ("{0}\{1}_wvd_packages.zip" -f $Path, $Build)) {
            Write-Host ("File found, renaming for backup purposes and creating new compressed archive...")
            Rename-Item -Path ("{0}\{1}_wvd_packages.zip" -f $Path, $Build) -NewName ("{0}\{1}_wvd_packages_bak_{2}.zip" -f $Path, $Build, (Get-Date -Format "MMddyyyy_HHmmss"))
        }
        Else { Write-Host ("File NOT FOUND - Creating new {0}_wvd_packages.zip..." -f $Build) }
                
        $buildPackages = ("{0}\{1}\Packages" -f $Path, $Build)
        $buildCompressedArchive = ("{0}\{1}\{1}_wvd_packages.zip" -f $Path, $Build)

        try {
            If ((Get-ChildItem -Path $buildPackages).Count -gt 0) {
                Write-Host ("Creating zip from {0} packages" -f $Build)
                Compress-Archive -Path $buildPackages -DestinationPath $buildCompressedArchive -CompressionLevel Optimal -Force
            
                $Result = Get-ChildItem -Path $buildCompressedArchive -ErrorAction Stop
                $Value = $Result.Length.ToString().Length
                If ($Value -le 6) { $fileSize = ("{0:N2} KB" -f ($Result.Length / 1KB)) }
                ElseIf ($Value -le 9 -AND $Value -gt 6) { $fileSize = ("{0:N2} MB" -f ($Result.Length / 1MB)) }
                ElseIf ($Value -ge 10) { $fileSize = ("{0:N2} GB" -f ($Result.Length / 1GB)) }

                Write-Host ("{0} WVD Package Zip ({1}) Created at: {2}" -f $Build, $fileSize, $Result.CreationTime)
            }
            Else {Write-Warning ("No items found in {0} Packages directory - no zip file created" -f $Build)}
        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
    }
}     