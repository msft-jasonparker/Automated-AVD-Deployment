[CmdletBinding()]
Param()
# Get function and internal module definition files.
$Functions = @( Get-ChildItem -Path $PSScriptRoot\Functions\*.ps1 -ErrorAction SilentlyContinue )
$Internal = @( Get-ChildItem -Path $PSScriptRoot\Internal\*.ps1 -ErrorAction SilentlyContinue )

# Dot source the files (exports to the console)
Foreach ($File in @($Functions + $Internal)) {
    Try { . $File.Fullname }
    Catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
}

# Do not use Export-ModuleMember, instead ensure the functions in the Functions folder are listed in the FunctionsToExport