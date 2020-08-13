[CmdletBinding()]
Param (
    [Parameter(Mandatory=$true)]
    [System.String]$HostPoolName,
    [Parameter(Mandatory=$true)]
    [System.String]$ResourceGroupName,
    [Parameter(Mandatory=$true)]
    [System.String]$SessionHostGroup
)

BEGIN {
    $sessionHosts = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName
}
PROCESS {

}

$hostpoolsdeployed = [[PSCustomObject]@{
    hostpoolname = vac30-wvd-hostpool-13
    sessionhostnames = 
    }
}]