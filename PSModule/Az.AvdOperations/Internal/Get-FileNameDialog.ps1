Function Get-FileNameDialog {
    [CmdletBinding()]
    Param (
        $InitialDirectory,
        $Filter = "All files (*.*)| *.*"
    )
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null 
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    If ($InitialDirectory) { $OpenFileDialog.initialDirectory = $InitialDirectory }
    Else { $OpenFileDialog.InitialDirectory = $env:OneDrive }
    $OpenFileDialog.Multiselect = $true
    $OpenFileDialog.RestoreDirectory = $true
    $OpenFileDialog.filter = $Filter
    $OpenFileDialog.ShowDialog() | Out-Null
    If ($OpenFileDialog.FileNames) { Return $OpenFileDialog.FileNames }
    Else { Return $OpenFileDialog.filename }
}