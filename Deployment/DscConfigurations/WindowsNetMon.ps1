Configuration WindowsNetMon
{
    Set-ExecutionPolicy "RemoteSigned" -Scope Process -Confirm:$false
    Set-ExecutionPolicy "RemoteSigned" -Scope CurrentUser -Confirm:$false

    Import-DSCResource -ModuleName "PSDesiredStateConfiguration"
    Import-DSCResource -ModuleName "xPSDesiredStateConfiguration"

    Node localhost
    {
        #Create directory for package zip file
        File CreatePackageDirectory
        {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = "C:\Temp\packages"
        }
        # Download and extract zip containing baseline packages
        File DownloadPackage
        {
            Ensure = "Present"
            SourcePath = "\\###SOURCE-PATH###\NM34_x64.exe"
            DestinationPath = "C:\Temp\packages\NM34_x64.exe"
            Type = "File"
            Force = $true
            DependsOn = "[File]CreatePackageDirectory"
        }
        # Install package
        xPackage NetworkMonitor
        {
            Ensure = "Present"
            Name = "Microsoft Network Monitor 3.4"
            Path = "C:\Temp\packages\NM34_x64.exe"
            ProductId = ''
            Arguments = "/Q"
            IgnoreReboot = $true
        }
    }
}
