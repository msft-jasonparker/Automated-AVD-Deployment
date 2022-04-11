Function New-AzAvdLogEntry {
    <#
        .SYNOPSIS
            Writes a log entry into an Azure Log Analytics workspace in a Custom Log table.
        .DESCRIPTION
            After creating a log entry using the  _NewComplianceLogEntry function, this function will inject the log entry into an Azure Log Analytics workspace. Provide the workspace id, shared key, custom table name, and the $logentry variable. If the custom log exists, it adds the data to the table, otherwise it will create the table.
    #>
    [CmdletBinding()]
    Param (
        $customerId,
        $sharedKey,
        $logName,
        $logMessage,
        [Switch]$PassThru
    )

    BEGIN {
        Function _GetLAAuthorization {
            [CmdletBinding()]
            Param(
                $customerId,
                $sharedKey,
                $date,
                $contentLength,
                $method,
                $contentType,
                $resource
            )
            $xHeaders = "x-ms-date:" + $date
            $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
            $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
            $keyBytes = [Convert]::FromBase64String($sharedKey)
            $sha256 = New-Object System.Security.Cryptography.HMACSHA256
            $sha256.Key = $keyBytes
            $calculatedHash = $sha256.ComputeHash($bytesToHash)
            $encodedHash = [Convert]::ToBase64String($calculatedHash)
            $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
            return $authorization
        }
    }
    PROCESS {
        If ($PassThru) {
            If ($logMessage.Count -gt 1) { $logMessage | ForEach-Object { Write-Host $_ -ForegroundColor Yellow } }
            Else { Write-Host $logMessage -ForegroundColor Yellow }
        }
        Else {
            $logJSON = $logMessage | ConvertTo-Json
            $body = ([System.Text.Encoding]::UTF8.GetBytes($logJSON))
            $method = "POST"
            $contentType = "application/json"
            $resource = "/api/logs"
            $rfc1123date = [DateTime]::UtcNow.ToString("r")
            $contentLength = $body.Length
            $signature = _GetLAAuthorization -customerId $customerId -sharedKey $sharedKey -date $rfc1123date -contentLength $contentLength -method $method -contentType $contentType -resource $resource 
            $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
            $OMSheaders = @{
                "Authorization"        = $signature;
                "Log-Type"             = $logName;
                "x-ms-date"            = $rfc1123date;
                "time-generated-field" = "Timestamp";
            }
    
            try {
                Invoke-WebRequest -Uri $uri -Method POST -ContentType $contentType -Headers $OMSheaders -Body $body -UseBasicParsing | Out-Null
            }
            catch {
                Write-Warning $_.Exception.Message
            }
        }
    }
}