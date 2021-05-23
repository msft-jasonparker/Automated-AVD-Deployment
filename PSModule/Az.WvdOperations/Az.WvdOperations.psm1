# Get Public and Private functions
$Public = @( Get-ChildItem -Path $PSScriptRoot\Public -Filter *.ps1 -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private -Filter *.ps1 -ErrorAction SilentlyContinue )

# Dot source the files
Foreach ($Function in @($Public + $Private))
{
    Try
    {
        Write-Verbose ("Loading function: {0}" -f $Function.Name)
        . $Function.FullName
    }
    Catch
    {
        Write-Error -Message ("Failed to import function ({0}): {1}" -f $Function.FullName, $_)
    }
}

# Export only the public functions
Export-ModuleMember -Function $Public.Basename