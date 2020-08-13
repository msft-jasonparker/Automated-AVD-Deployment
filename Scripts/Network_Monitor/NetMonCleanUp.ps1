# Netmon clean up script
$path = "C:\Windows\Utilities\NetMon"
If (Test-Path -Path $path) {
    Get-ChildItem -Path $path -Filter *.cap | ? {$_.LastWriteTime -lt (Get-Date).AddDays(-3)} | Remove-Item -Force
}