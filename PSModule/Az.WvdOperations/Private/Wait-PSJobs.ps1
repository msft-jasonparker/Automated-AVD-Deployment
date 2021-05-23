Function Wait-PSJobs {
    <#
        .SYNOPSIS
            Waits upto 60 minutes for background jobs to finish, otherwise, stops the jobs
        .DESCRIPTION
            Creates a while loop for running jobs. If a background job is running for longer than the -maxDuration, the job will be stopped to prevent an endless job loop.
    #>
    [CmdletBinding()]
    Param (
        # Array of current jobs
        [System.Collections.ArrayList]$Jobs = @(Get-Job),

        # Maximum number of minutes to allow the the jobs to run to completion
        [System.Int32]$maxDuration = 60
    )

    $timeSpan = [timespan]::FromMinutes($maxDuration)
    Write-Host ("Waiting on Jobs") -NoNewline
    While (($Jobs | Where-Object {$_.State -eq "Running"}).Count -gt 0) {
        $utcNow = [DateTime]::UtcNow
        Foreach ($Job in ($Jobs | Where-Object {$_.State -eq "Running"})) {
            If ($utcNow.Subtract($Job.PSBeginTime.ToUniversalTime()) -gt $timeSpan) {
                $Job | Stop-Job -Confirm:$false
            }
        }
        Write-Host (".") -NoNewline
        Start-Sleep -Milliseconds 2500
    }
    Write-Host ("Done!")
}