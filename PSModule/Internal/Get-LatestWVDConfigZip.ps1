Function Get-LatestWVDConfigZip {
    <#
        .SYNOPSIS
            Fetches the latest WVD Configuration zip file for WVD Deployments
        .DESCRIPTION
            This function takes no parameters and simply fetches the latest configuration zip file for WVD Deployments from the Microsoft WVD Product Group
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [System.String]$LocalPath,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Local", "Remote")]
        [System.String]$OutputType
    )
    try {
        If ($OutputType -eq "Local" -and [System.String]::IsNullOrEmpty($LocalPath)) {
            Write-Warning ("OutputType is 'Local', but LocalPath is empty, defaulting to 'Remote' OutputType")
            $OutputType = "Remote"
        }
        ElseIf ($OutputType -eq "Remote" -and (![System.String]::IsNullOrEmpty($LocalPath))) { Write-Warning ("OutputType is 'Remote' and LocalPath is defined, ignoring LocalPath") }
        Else { Write-Verbose ("WVD Configuration output type: {0}" -f $OutputType) }

        [xml]$results = (Invoke-WebRequest -Uri "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts?restype=container&comp=list" -UseBasicParsing -ErrorAction SilentlyContinue).Content.Substring(3)
        If ($results.EnumerationResults.Blobs.Blob.Count -gt 0) {
            Write-Verbose ("Found {0} Blobs for WVD Configuration" -f $results.EnumerationResults.Blobs.Blob.Count)
            [System.Collections.ArrayList]$list = @()
            $x = $results.EnumerationResults.Blobs.Blob | Where-Object { $_.Name -like "Configuration_*" }
            $x | ForEach-Object {
                $dateindex = $_.Name.IndexOf("_")
                $config = $_ | Select-Object Url, @{l = 'Date'; e = { $_.Name.Substring($dateindex + 1).Split(".")[0] | Get-Date } }
                [void]$list.Add($config)
            }

            If ($OutputType -eq "Remote") { Return ($list | Sort-Object Date -Descending | Select-Object -First 1).Url }
            Else {
                If (Test-Path -Path $LocalPath) {
                    Write-Verbose ("Mininum Time: {0}" -f (Get-Date).AddHours(-6))
                    If (Test-Path -Path ("{0}\wvdConfiguration.zip" -f $LocalPath)) {
                        $wvdConfigurationZip = Get-ChildItem -Path ("{0}\wvdConfiguration.zip" -f $LocalPath) -File
                        Write-Verbose ("LastWriteTime: {0}" -f $wvdConfigurationZip.LastWriteTime)
                        If (((Get-Date) - $wvdConfigurationZip.LastWriteTime).TotalHours -gt 6) {
                            Write-Host ("File Age: {0}" -f ((Get-Date) - $wvdConfigurationZip.LastWriteTime).TotalHours)
                            Write-Verbose ("Downloading new WVD Configuration Zip file")
                            $latestZipUri = ($list | Sort-Object Date -Descending | Select-Object -First 1).Url
                            (New-Object System.Net.WebClient).DownloadFile($latestZipUri, ("{0}\wvdConfiguration.zip" -f $LocalPath))
                            $wvdConfigurationZip = Get-ChildItem -Path ("{0}\wvdConfiguration.zip" -f $LocalPath) -File
                            If ($wvdConfigurationZip) { Return $wvdConfigurationZip.FullName }
                        }
                        Else {
                            Write-Warning ("WVD Configuration Zip file is less than 6 hours old, using current file")
                            Return $wvdConfigurationZip.FullName 
                        }
                    }
                    Else {
                        Write-Verbose ("Downloading new WVD Configuration Zip file")
                        $latestZipUri = ($list | Sort-Object Date -Descending | Select-Object -First 1).Url
                        (New-Object System.Net.WebClient).DownloadFile($latestZipUri, ("{0}\wvdConfiguration.zip" -f $LocalPath))
                        $wvdConfigurationZip = Get-ChildItem -Path ("{0}\wvdConfiguration.zip" -f $LocalPath) -File -ErrorAction SilentlyContinue
                        If ($wvdConfigurationZip) { Return $wvdConfigurationZip.FullName }
                    }
                }
                Else {
                    Write-Warning ("The LocalPath defined does not exist ({0})" -f $LocalPath)
                    Write-Verbose ("Invalid LocalPath, using remote path!")
                    Return ($list | Sort-Object Date -Descending | Select-Object -First 1).Url
                }
            }
        }
        Else {
            If ($OutputType -eq "Remote") { Return "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration.zip" }
            Else {
                If (Test-Path -Path ("{0}\wvdConfiguration.zip" -f $LocalPath)) {
                    $wvdConfigurationZip = Get-ChildItem -Path ("{0}\wvdConfiguration.zip" -f $LocalPath) -File
                    If ($wvdConfigurationZip) { Return $wvdConfigurationZip.FullName }
                }
                Else {
                    Write-Warning ("The LocalPath defined does not exist ({0})" -f $LocalPath)
                    Write-Verbose ("Invalid LocalPath, using remote path!")
                    Return "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration.zip"
                }
            }
        }
    }
    catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
}