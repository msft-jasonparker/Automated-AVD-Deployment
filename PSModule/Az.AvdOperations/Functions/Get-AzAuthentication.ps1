Function Get-AzAuthentication {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("Global","Local","Script")]
        [System.String]$Scope = "Script"
    )
    try {
        $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
        If ($azProfile.Contexts.Count -eq 0) {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::New(
                    [System.SystemException]::New(("No Azure Context(s) found - Run Connect-AzAccount before calling this command")),
                    "NoAzureAuthenticationFound",
                    [System.Management.Automation.ErrorCategory]::AuthenticationError,
                    ("No Contexts Found")
                )
            )
        }
        Else {
            Switch ($Scope) {
                "Global" { $Global:AzAuthentication = $azProfile.DefaultContext }
                "Local" { $Local:AzAuthentication = $azProfile.DefaultContext }
                "Script" {
                    Write-Warning ("Default Scope set to 'SCRIPT'. The `$AzAuthentication variable may not be exposed unless it is embedded in a script or function.")
                    $SCRIPT:AzAuthentication = $azProfile.DefaultContext
                }
            }
        }
    }
    catch [System.Management.Automation.RuntimeException] {
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::New(
                [System.SystemException]::New(("Failed to find Azure Profile Provider. Run Connect-AzAccount for your environment before calling this command.")),
                "AzureProfileProviderMissing",
                [System.Management.Automation.ErrorCategory]::AuthenticationError,
                ("No Auzre Profile Provider")
            )
        )
    }
}