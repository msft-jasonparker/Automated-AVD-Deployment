Configuration WvdWin10Config
{
    Param (
        [string]$HostPoolName,
        [string]$RegistrationInfoToken,
        [string]$DeploymentPurpose,
        [string]$DeploymentType,
        [string]$fsLogixVhdLocation
    )
    Set-ExecutionPolicy "RemoteSigned" -Scope Process -Confirm:$false
    Set-ExecutionPolicy "RemoteSigned" -Scope CurrentUser -Confirm:$false

    Import-DSCResource -ModuleName "PSDesiredStateConfiguration"
    Import-DSCResource -ModuleName "xPSDesiredStateConfiguration"
    Import-DscResource -ModuleName "CertificateDsc"
    Import-DscResource -ModuleName "ComputerManagementDsc"
    Import-DscResource -ModuleName "PowerShellModule"
    Import-Module -Name BitsTransfer -force

    $vaConfigDataPath = "C:\ProgramData\DeptOfVeteransAffairs"
    Start-BitsTransfer -Source "https://datrgallerycontainer.blob.core.windows.net/gallaryartifacts/Configuration.zip" -Destination ($env:TEMP + "\wvdConfiguration.zip")
    If (Test-Path -Path ($env:TEMP + "\wvdConfiguration.zip")) { Expand-Archive -Path ($env:TEMP + "\wvdConfiguration.zip") -DestinationPath ($vaConfigDataPath + "\WVD") -Force}
    . ($vaConfigDataPath + "\WVD\Functions.ps1")

    #Add-LocalGroupMember -Group "Administrators" -Member ("VA\VAOITWindowVirtualDesktop","VA\VAOITWindowsVirtualDesktop") -ErrorAction SilentlyContinue

    Node localhost {
        ## Local Administrators
        Script LocalAdministratorsGroup {
            GetScript = { return @{'Result' = ''} }
            SetScript = { Add-LocalGroupMember -Group "Administrators" -Member "VA\VAOITWindowsVirtualDesktop" -ErrorAction SilentlyContinue }
            TestScript = {
                $Members = Get-LocalGroupMember -Group "Administrators" | Foreach-Object {$_.Name}
                If ($Members -contains "VA\VAOITWindowsVirtualDesktop") { Return $false }
                Else { Return $true }
            }
        }
        ## Certificate Imports
        xRemoteFile 'DownloadVAInternalRoot' {
            DestinationPath = 'C:\Temp\Certs\VAInternalRoot.cer'
            Uri = 'http://aia.pki.va.gov/pki/aia/va/VAInternalRoot.cer'
        }
        xRemoteFile 'DownloadVA-Internal-S2-RCA1-v1' {
            DestinationPath = 'C:\Temp\Certs\VA-Internal-S2-RCA1-v1.cer'
            Uri = 'http://aia.pki.va.gov/pki/aia/va/VA-Internal-S2-RCA1-v1.cer'
        }
        xRemoteFile 'DownloadVA-Internal-S2-ICA2-v1' {
            DestinationPath = 'C:\Temp\Certs\VA-Internal-S2-ICA2-v1.cer'
            Uri = 'http://aia.pki.va.gov/pki/aia/va/VA-Internal-S2-ICA2-v1.cer'
        }
        xRemoteFile 'DownloadVA-Internal-S2-ICA1-v1' {
            DestinationPath = 'C:\Temp\Certs\VA-Internal-S2-ICA1-v1.cer'
            Uri = 'http://aia.pki.va.gov/pki/aia/va/VA-Internal-S2-ICA1-v1.cer'
        }
        xRemoteFile 'DownloadInternalSubCA2' {
            DestinationPath = 'C:\Temp\Certs\InternalSubCA2.cer'
            Uri = 'http://aia.pki.va.gov/pki/aia/va/InternalSubCA2.cer'
        }
        xRemoteFile 'DownloadInternalSubCA1' {
            DestinationPath = 'C:\Temp\Certs\InternalSubCA1.cer'
            Uri = 'http://aia.pki.va.gov/pki/aia/va/InternalSubCA1.cer'
        }
        CertificateImport VAInternalRoot {
            Thumbprint = '063A4153CAC6F14661DA8E52DCF47161F0C13810'
            Location   = 'LocalMachine'
            Store      = 'Root'
            Path       = 'C:\Temp\Certs\VAInternalRoot.cer'
            Ensure     = 'Present'
            DependsOn  = '[xRemoteFile]DownloadVAInternalRoot'
        }
        CertificateImport VA-Internal-S2-RCA1-v1 {
            Thumbprint = '6EAB28328741339C91E12A269DE40C42894513CE'
            Location   = 'LocalMachine'
            Store      = 'CA'
            Path       = 'C:\Temp\Certs\VA-Internal-S2-RCA1-v1.cer'
            Ensure     = 'Present'
            DependsOn  = '[xRemoteFile]DownloadVA-Internal-S2-RCA1-v1'
        }
        CertificateImport VA-Internal-S2-ICA2-v1 {
            Thumbprint = '704C9C2288D79DBDB3BA0E647CFE31A181D01CB2'
            Location   = 'LocalMachine'
            Store      = 'CA'
            Path       = 'C:\Temp\Certs\VA-Internal-S2-ICA2-v1.cer'
            Ensure     = 'Present'
            DependsOn  = '[xRemoteFile]DownloadVA-Internal-S2-ICA2-v1'
        }
        CertificateImport VA-Internal-S2-ICA1-v1 {
            Thumbprint = 'C702BBAAB2A41E74EF129AEB279B388F878E87D6'
            Location   = 'LocalMachine'
            Store      = 'CA'
            Path       = 'C:\Temp\Certs\VA-Internal-S2-ICA1-v1.cer'
            Ensure     = 'Present'
            DependsOn  = '[xRemoteFile]DownloadVA-Internal-S2-ICA1-v1'
        }
        CertificateImport InternalSubCA2 {
            Thumbprint = '5BB2BBE7C983A1A586600AD64A13E3DAFAFBFECA'
            Location   = 'LocalMachine'
            Store      = 'CA'
            Path       = 'C:\Temp\Certs\InternalSubCA2.cer'
            Ensure     = 'Present'
            DependsOn  = '[xRemoteFile]DownloadInternalSubCA2'
        }
        CertificateImport InternalSubCA1 {
            Thumbprint = 'A895F47601DF8973FCB65EEF63F581F4FA9DDFB7'
            Location   = 'LocalMachine'
            Store      = 'CA'
            Path       = 'C:\Temp\Certs\InternalSubCA1.cer'
            Ensure     = 'Present'
            DependsOn  = '[xRemoteFile]DownloadInternalSubCA1'
        }
        # Create VA configuration data directory
        File CreateVAConfigDataPath {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $vaConfigDataPath
        }
        #Create directory for package zip file
        File CreatePackageDirectory {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = ("{0}\DSC" -f $vaConfigDataPath)
        }
        #Create directory for MSI logs
        File CreateLogDirectory {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = ("{0}\Logs" -f $vaConfigDataPath)
        }
         # Download and extract zip containing baseline packages
         File DownloadPackage {
            Ensure = "Present"
            SourcePath = "\\vac30hsm01-6833.va.gov\vac30-wvd-netapp-pool01-vol01\wvdartifacts\wvd_packages.zip"
            DestinationPath = ("{0}\wvd_packages.zip" -f $env:TEMP)
            Type = "File"
            Force = $true
        }
        xArchive ExtractPackages {
            Ensure = "Present"
            Path = ("{0}\wvd_packages.zip" -f $env:TEMP)
            Destination = ("{0}\DSC" -f $vaConfigDataPath)
            DependsOn = "[File]DownloadPackage"
            Force = $true
        }
        File VAOEMLogoDirectory {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = ("{0}\ESE-DT\OEMLogo" -f $vaConfigDataPath)
            DependsOn = "[xArchive]ExtractPackages"
        }
        File CopyVAOEMLogoIntoDirectory {
            Ensure = "Present"
            SourcePath = ("{0}\DSC\Packages\VA GFE Branding\OemLogo.bmp" -f $vaConfigDataPath)
            DestinationPath = ("{0}\ESE-DT\OEMLogo\OemLogo.bmp" -f $vaConfigDataPath)
            Type = "File"
            Force = $true
            DependsOn = "[File]VAOEMLogoDirectory"
        }
        File CopyVAYourITIcon {
            Ensure = "Present"
            SourcePath = ("{0}\DSC\Packages\YourIT Icon\YourIT.ico" -f $vaConfigDataPath)
            DestinationPath = "C:\Users\Public\Pictures\YourIT.ico"
            Type = "File"
            Force = $true
            DependsOn = "[xArchive]ExtractPackages"
        }
        #Create directory used for the Citrix install
        File CreateCitrixInstallDirectory {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = "%ALLUSERSPROFILE%\DeptOfVeteransAffairs\Software\CitrixWorkspace1911\"
            DependsOn = "[xArchive]ExtractPackages"
        }

        # WVD HostPool Registration
        #. ("{0}\DSC\Packages\WVD_OnBoarding\Functions.ps1" -f $vaConfigDataPath)
        If (Get-Command -Name isRdshServer) {
            $rdshIsServer = isRdshServer
            if ($rdshIsServer) {
                "$(get-date) - rdshIsServer = true: $rdshIsServer" | out-file c:\windows\temp\rdshIsServerResult.txt -Append
                WindowsFeature RDS-RD-Server {
                    Ensure = "Present"
                    Name = "RDS-RD-Server"
                }
    
                Script ExecuteRdAgentInstallServer {
                    DependsOn = "[WindowsFeature]RDS-RD-Server","[xArchive]ExtractPackages"
                    GetScript = { return @{'Result' = ''} }
                    SetScript = {
                        try { & "$using:vaConfigDataPath\DSC\Packages\WVD_OnBoarding\Script-AddRdshServer.ps1" -HostPoolName $using:HostPoolName -RegistrationInfoToken $using:RegistrationInfoToken -EnableVerboseMsiLogging:($using:EnableVerboseMsiLogging) }
                        catch {
                            $ErrMsg = $PSItem | Format-List -Force | Out-String
                            Write-Log -Err $ErrMsg
                            throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallServer SetScript: $ErrMsg", $PSItem.Exception)
                        }
                    }
                    TestScript = {
                        try { return (Test-path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent") }
                        catch {
                            $ErrMsg = $PSItem | Format-List -Force | Out-String
                            Write-Log -Err $ErrMsg
                            throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallServer TestScript: $ErrMsg", $PSItem.Exception)
                        }
                    }
                }
            }
            else {
                "$(get-date) - rdshIsServer = false: $rdshIsServer" | out-file c:\windows\temp\rdshIsServerResult.txt -Append
                Script ExecuteRdAgentInstallClient {
                    DependsOn = "[xArchive]ExtractPackages"
                    GetScript = { return @{'Result' = ''} }
                    SetScript = {
                        try { & "$using:vaConfigDataPath\DSC\Packages\WVD_OnBoarding\Script-AddRdshServer.ps1" -HostPoolName $using:HostPoolName -RegistrationInfoToken $using:RegistrationInfoToken -EnableVerboseMsiLogging:($using:EnableVerboseMsiLogging) }
                        catch {
                            $ErrMsg = $PSItem | Format-List -Force | Out-String
                            Write-Log -Err $ErrMsg
                            throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallClient SetScript: $ErrMsg", $PSItem.Exception)
                        }
                    }
                    TestScript = {
                        try { return (Test-path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent") }
                        catch {
                            $ErrMsg = $PSItem | Format-List -Force | Out-String
                            Write-Log -Err $ErrMsg
                            throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallClient TestScript: $ErrMsg", $PSItem.Exception)
                        }
                    }
                }
            }
        }
        Else { "$(get-date) - Failed to find isRdshServer command - module didn't import" | out-file c:\windows\temp\rdsh-function-import.txt -Append }

        #VDI/WVD Optimization Script
        Script VDI_Optimize {
            TestScript = {
                if ((Get-ScheduledTask MapsToastTask).State -eq "Disabled") { return $true }
                else { return $false }
            }
            SetScript = { powershell.exe -NonInteractive -File "$using:vaConfigDataPath\DSC\Packages\optimizations\1909\Win10_1909_VDI_Optimize.ps1" }
            GetScript = {
                @{ Result = ((Get-ScheduledTask MapsToastTask).State) }
            }
            DependsOn = "[xArchive]ExtractPackages"
        }        
        #Copy Citrix Workspace executable to install source directory
        File CopyCitrixWorkspaceExe {
            Ensure = "Present"
            SourcePath = ("{0}\DSC\Packages\Citrix Workspace\19.11.0.50\MSI\CitrixWorkspaceAppWeb.exe" -f $vaConfigDataPath)
            DestinationPath = "%ALLUSERSPROFILE%\DeptOfVeteransAffairs\Software\CitrixWorkspace1911\CitrixWorkspaceAppWeb.exe"
            Type = "File"
            Force = $true
            DependsOn = "[File]CreateCitrixInstallDirectory"
        }
        ## Network Tracing
        File CreateUtilitiesDirectory {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = "C:\Windows\Utilities\NetMon"
        }
        File CopyNetMonUtilities {
            Ensure = "Present"
            Type = "File"
            SourcePath = ("{0}\DSC\Packages\NetworkTracing\NetMonCleanUp.ps1" -f $vaConfigDataPath)
            DestinationPath = "C:\Windows\Utilities\NetMonCleanUp.ps1"
            Force = $true
            DependsOn = "[File]CreateUtilitiesDirectory"
        }
        xPackage NetworkMonitor {
            Ensure = "Present"
            Name = "Microsoft Network Monitor 3.4"
            Path = ("{0}\DSC\Packages\NetworkTracing\NM34_x64.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = "/Q"
            IgnoreReboot = $true
        }
        ScheduledTask EnableNetMonTracing {
            Ensure = "Present"
            Enable = $true
            TaskName = "NetMonCapture"
            TaskPath = "\Microsoft\Windows\NetTrace"
            ActionExecutable = "C:\Program Files\Microsoft Network Monitor 3\nmcap.exe"
            ActionArguments = "/Network * /Capture /MaxFrameLength 256 /File C:\Windows\Utilities\NetMon\%computername%.chn:250MB"
            Description = "Starts NetMon Tracing at user logon"
            ScheduleType = "AtLogon"
            BuiltInAccount = "SYSTEM"
            Priority = 7
            RunLevel = "Highest"
            MultipleInstances = "IgnoreNew"
            RunOnlyIfIdle = $false
            DependsOn = "[xPackage]NetworkMonitor"
        }
        ScheduledTask NetMonTracingCleanUp {
            Ensure = "Present"
            Enable = $true
            TaskName = "NetMonCleanUp"
            TaskPath = "\Microsoft\Windows\NetTrace"
            ActionExecutable = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            ActionArguments = "-NoProfile -NonInteractive -File NetMonCleanUp.ps1"
            ActionWorkingPath = "C:\Windows\Utilities"
            Description = "Runs PowerShell script to clean up old NetMon capture files"
            StartTime = '2020-01-01T10:00:00'
            SynchronizeAcrossTimeZone = $true
            ScheduleType = "Daily"
            DaysInterval = 1
            ExecutionTimeLimit = "01:00:00"
            BuiltInAccount = "SYSTEM"
            Priority = 7
            RunLevel = "Highest"
            MultipleInstances = "IgnoreNew"
            RunOnlyIfIdle = $false
            DependsOn = "[ScheduledTask]EnableNetMonTracing"
        }
        #Scheduled task to start Smart Card Service (ScardSvr)
        ScheduledTask StartSmartCardService {
            Ensure = "Present"
            Enable = $true
            TaskName = "StartSmartCardService"
            TaskPath = "\Microsoft\Windows\SmartCard"
            ActionExecutable = "C:\windows\system32\net.exe"
            ActionArguments = "start scardsvr"
            Description = "Starts the Smart Card Service whenever it is stopped"
            ScheduleType = "OnEvent"
            EventSubscription = '<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[Provider[@Name="Service Control Manager"] and (EventID=7036)]]</Select></Query></QueryList>'
            BuiltInAccount = "SYSTEM"
            Priority = 7
            RunLevel = "Highest"
            MultipleInstances = "IgnoreNew"
            RunOnlyIfIdle = $false
        }
        # Install packages
        xPackage VCRedist2008x64 {
            Ensure = "Present"
            Name = "Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161"
            Path = ("{0}\DSC\Packages\Redistributables\Visual C++ 2008 Redistributable\9.0.30729.6161\MSI\vcredist_x64.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = "/q /l $vaConfigDataPath\Logs\Microsoft_VisualC++2008_Redistributablex64_9.0.30729.6161.log"
            IgnoreReboot = $true
        }
        xPackage VCRedist2008x86 {
            Ensure = "Present"
            Name = "Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161"
            Path = ("{0}\DSC\Packages\Redistributables\Visual C++ 2008 Redistributable\9.0.30729.6161\MSI\vcredist_x86.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = "/q /l $vaConfigDataPath\Logs\Microsoft_VisualC++2008_Redistributablex86_9.0.30729.6161.log"
            IgnoreReboot = $true
        }
        xPackage VCRedist2012x86 {
            Ensure = "Present"
            Name = "Microsoft Visual C++ 2012 Redistributable (x86) - 11.0.61030"
            Path = ("{0}\DSC\Packages\Redistributables\Visual C++ 2012 Redistributable\11.0.61030.0\MSI\vcredist_x86.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = "/q /l $vaConfigDataPath\Logs\Microsoft_VisualC++2012_Redistributablex86_11.0.61030.0.log"
            IgnoreReboot = $true
        }
        xPackage VCRedist2012x64 {
            Ensure = "Present"
            Name = "Microsoft Visual C++ 2012 Redistributable (x64) - 11.0.61030"
            Path = ("{0}\DSC\Packages\Redistributables\Visual C++ 2012 Redistributable\11.0.61030.0\MSI\vcredist_x64.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = "/q /l $vaConfigDataPath\Logs\Microsoft_VisualC++2012_Redistributablex64_11.0.61030.0.log"
            IgnoreReboot = $true
        }
        xPackage VCRedist2013x86 {
            Ensure = "Present"
            Name = "Microsoft Visual C++ 2013 Redistributable (x86) - 12.0.40664"
            Path = ("{0}\DSC\Packages\Redistributables\Visual C++ 2013 Redistributable\12.0.40664.0\MSI\vcredist_x86.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = "/q /l $vaConfigDataPath\Logs\Microsoft_VisualC++2013_Redistributablex86_12.0.40664.0.log"
            IgnoreReboot = $true
        }
        xPackage VCRedist2013x64 {
            Ensure = "Present"
            Name = "Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.40664"
            Path = ("{0}\DSC\Packages\Redistributables\Visual C++ 2013 Redistributable\12.0.40664.0\MSI\vcredist_x64.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = "/q /l $vaConfigDataPath\Logs\Microsoft_VisualC++2013_Redistributablex86_12.0.40664.0.log"
            IgnoreReboot = $true
        }
        xPackage VCRedist2019x86 {
            Ensure = "Present"
            Name = "Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.25.28508"
            Path = ("{0}\DSC\Packages\Redistributables\Visual C++ 2019 Redistributable\14.25.28508.3\MSI\VC_redist.x86.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = "/q /l $vaConfigDataPath\Logs\Microsoft_VisualC++2019_Redistributablex86_14.25.28508.0.log"
            IgnoreReboot = $true
        }
        xPackage VCRedist2019x64 {
            Ensure = "Present"
            Name = "Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.25.28508"
            Path = ("{0}\DSC\Packages\Redistributables\Visual C++ 2019 Redistributable\14.25.28508.3\MSI\VC_redist.x64.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = "/q /l $vaConfigDataPath\Logs\Microsoft_VisualC++2019_Redistributablex64_14.25.28508.0.log"
            IgnoreReboot = $true
        }
        If ($DeploymentPurpose -eq "ITOPS") {
            WindowsCapability AdminToolsFileServices {
                Ensure = "Present"
                Name = "Rsat.FileServices.Tools~~~~0.0.1.0"
            }
            WindowsCapability AdminToolsDHCP {
                Ensure = "Present"
                Name = "Rsat.DHCP.Tools~~~~0.0.1.0"
            }
            WindowsCapability AdminToolsDNS {
                Ensure = "Present"
                Name = "Rsat.Dns.Tools~~~~0.0.1.0"
            }
            WindowsCapability AdminToolsActiveDirectory {
                Ensure = "Present"
                Name = "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
            }
            WindowsCapability AdminToolsGroupPolicy {
                Ensure = "Present"
                Name = "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
            }
            xPackage AdminToolsSqlServerMgmt {
                Ensure = "Present"
                Name = "Microsoft SQL Server Management Studio - 18.6"
                Path = ("{0}\DSC\Packages\SQLServerMgmtStudio\SSMS-Setup-ENU.exe" -f $vaConfigDataPath)
                ProductId = ''
                Arguments = '/Quiet'
                IgnoreReboot = $true
            }
            xPackage VisualStudioCode {
                Ensure = "Present"
                Name = "Microsoft Visual Studio Code"
                Path = ("{0}\DSC\Packages\VSCode_v1.47.3\VSCodeSetup-x64-1.47.3.exe" -f $vaConfigDataPath)
                ProductId = ''
                Arguments = ('/VERYSILENT /NORESTART /MERGETASKS=!runcode /LOG="{0}\Logs\VSCodeSetup-x64-1.47.3.log"' -f $vaConfigDataPath)
                IgnoreReboot = $true
            }
            xPackage Git {
                Ensure = "Present"
                Name = "Git version 2.28.0"
                Path = ("{0}\DSC\Packages\Git_v2.28.0\Git-2.28.0-64-bit.exe" -f $vaConfigDataPath)
                ProductId = ''
                Arguments = ('/VERYSILENT /NORESTART /LOG="{0}\Logs\Git-2.28.0-64-bit.log"' -f $vaConfigDataPath)
                IgnoreReboot = $true
            }
            PSModuleResource AzurePowerShellModule {
                Ensure = "Present"
                Module_Name = "Az"
            }
            PSModuleResource AzureADPowerShellModule {
                Ensure = "Present"
                Module_Name = "AzureAD"
            }
            PSModuleResource WVDPowerShellModule {
                Ensure = "Present"
                Module_Name = "Az.DesktopVirtualization"
            }
            PSModuleResource SPOPowerShellModule {
                Ensure = "Present"
                Module_Name = "Microsoft.Online.SharePoint.PowerShell"
            }
            PSModuleResource EXOPowerShellModule {
                Ensure = "Present"
                Module_Name = "ExchangeOnlineManagement"
            }
            File AdminToolsDesktopFolder {
                Ensure = "Present"
                Type = "Directory"
                DestinationPath = "C:\Users\Public\Desktop\Admin Tools"
            }
            Script CopyAdminToolShortcuts {
                DependsOn = "[File]AdminToolsDesktopFolder"
                GetScript = { @{ Result = ''} }
                TestScript = {
                    If (Test-Path -Path "C:\Users\Public\Desktop\Admin Tools") { Return $false }
                    Else { Return $true }
                }
                SetScript = { Copy-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\*.lnk" -Destination "C:\Users\Public\Desktop\Admin Tools" -Force }
            }
        }
        xPackage CitrixWorkspace {
            Ensure = "Present"
            Name = "Citrix Workspace 1911"
            Path = "C:\ProgramData\DeptOfVeteransAffairs\Software\CitrixWorkspace1911\CitrixWorkspaceAppWeb.exe"
            ProductId = ''
            Arguments = "/Silent /noreboot /forceinstall /includeSSON /ENABLE_SSON=Yes /AutoUpdateCheck=disabled SELFSERVICEMODE=False EnableCEIP=False EnableTracing=false"
            DependsOn = "[File]CopyCitrixWorkspaceExe"
            IgnoreReboot = $true
        }
        xPackage AdobeAcrobatReaderDC {
            Ensure = "Present"
            Name = "Adobe Acrobat Reader DC"
            Path = ("{0}\DSC\Packages\Adobe Acrobat Reader DC\20.006.20042\MSI\AcroRead.msi" -f $vaConfigDataPath)
            ProductId = "AC76BA86-7AD7-1033-7B44-AC0F074E4100"
            Arguments = ('TRANSFORMS="{0}\DSC\Packages\Adobe Acrobat Reader DC\20.006.20042\MSI\AcroRead.mst" /update "{0}\DSC\Packages\Adobe Acrobat Reader DC\20.006.20042\MSI\AcroRdrDCUpd2000620042.msp" EULA_ACCEPT=YES ALLUSERS=1 REBOOT=R' -f $vaConfigDataPath)
            LogPath = "$vaConfigDataPath\Logs\Adobe_Acrobat_Reader_DC_20.006.20042.log"
            IgnoreReboot = $true
        }  
        xPackage ePasSignatureTools {
            Ensure = "Present"
            Name = "ePas Signature Tools x86"
            Path = ("{0}\DSC\Packages\ePas Signature Tools\1.0.0 app\MSI\ePass.msi" -f $vaConfigDataPath)
            ProductId = "8D909042-AD1E-4145-B510-1E6863333BD4"
            Arguments = ('TRANSFORMS="{0}\DSC\Packages\ePas Signature Tools\1.0.0 app\MSI\ePass.mst" ALLUSERS=1 REBOOT=R' -f $vaConfigDataPath)
            LogPath = "$vaConfigDataPath\Logs\ePas_Signature_Tools_1.0.log"
            IgnoreReboot = $true
        }
        xPackage GemaltoSafeNetMiniDriverx64 {
            Ensure = "Present"
            Name = "SafeNet Minidriver 10.1"
            Path = ("{0}\DSC\Packages\Gemalto SafeNet MiniDriver\10.1.15\MSI\Gemalto SafeNet MiniDriverx64.msi" -f $vaConfigDataPath)
            ProductId = "960A22E8-6192-4C57-9F1A-CD14E13B38F1"
            Arguments = 'ALLUSERS=1 REBOOT=R /qn'
            LogPath = "$vaConfigDataPath\Logs\Gemalto_SafeNet_Minidriver_10.1.15.log"
            IgnoreReboot = $true
        }
        xPackage GuidanceSoftwareEnCaseEnterpriseAgent {
            Ensure = "Present"
            Name = "SAFE Agent"
            Path = ("{0}\DSC\Packages\Guidance Software EnCase Enterprise Agent\1.09.01.18\MSI\Setup.msi" -f $vaConfigDataPath)
            ProductId = "E39C38FC-343C-4D3D-8DCA-681C7FF8518A"
            Arguments = ('TRANSFORMS="{0}\DSC\Packages\Guidance Software EnCase Enterprise Agent\1.09.01.18\MSI\Setup.Mst" ENSTCMDLINE=-c ALLUSERS=1 REBOOT=R' -f $vaConfigDataPath)
            LogPath = "$vaConfigDataPath\Logs\Guidance_Software_SAFE_Agent_1.09.01.18.log"
            IgnoreReboot = $true
        }
        xPackage MicroFocusReflectionDLLfor2FA {
            Ensure = "Present"
            Name = "VA Micro Focus Reflection DLL for 2FA"
            Path = ("{0}\DSC\Packages\Micro Focus Reflection\Micro Focus Reflection DLL for 2FA\1.0.0.0\MSI\MicroFocusReflectionDLL.msi" -f $vaConfigDataPath)
            ProductId = "120E2C43-F216-495C-BD51-D3C678E3E8B8"
            Arguments = 'ALLUSERS=1 REBOOT=R'
            DependsOn = "[xPackage]ReflectionPro"
            IgnoreReboot = $true
        }
        xArchive Reflection {
            Ensure = "Present"
            Path = ("{0}\DSC\Packages\Micro Focus Reflection\Reflection\16.0.308 SP1\MSI\msi.zip" -f $vaConfigDataPath)
            Destination = "C:\Windows\Installer\Attachmate"
            DependsOn = "[xArchive]ExtractPackages"
            Force = $true
        }
        xPackage ReflectionPro {
            Ensure = "Present"
            Name = "Micro Focus Reflection Desktop Pro"
            Path = "C:\Windows\Installer\Attachmate\ReflectionProV16.msi"
            ProductId = 'BD7A978B-A1C4-4BE8-8AD9-A4736CBA3C70'
            Arguments = ('TRANSFORMS="C:\Windows\Installer\Attachmate\Reflection16-32Bit.Mst" /update "C:\Windows\Installer\Attachmate\reflection-16-service-pack-1.msp" /update "{0}\DSC\Packages\Micro Focus Reflection\Reflection Desktop Pro\16.0.478 Hotfix\MSI\T160478.msp" ALLUSERS=1' -f $vaConfigDataPath)
            LogPath = "$vaConfigDataPath\Logs\AttachmateReflection_16.log"
            DependsOn = "[xPackage]ReflectionProVBA711033"
            IgnoreReboot = $true
        }
        xPackage ReflectionProVBA71 {
            Ensure = "Present"
            Name = "Microsoft Visual Basic for Applications 7.1 (x86)"
            Path = "C:\Windows\Installer\Attachmate\Vba71.msi"
            ProductId = '90120000-0070-0000-0000-4000000FF1CE'
            Arguments = 'ALLUSERS=1 REBOOT=R'
            LogPath = "$vaConfigDataPath\Logs\VBA71.log"
            DependsOn = "[xArchive]Reflection"
            IgnoreReboot = $true
        }
        xPackage ReflectionProVBA711033 {
            Ensure = "Present"
            Name = "Microsoft Visual Basic for Applications 7.1 (x86) English"
            Path = 'C:\Windows\Installer\Attachmate\Vba71_1033.msi'
            ProductId = 'BAB89D31-4C55-472B-8909-6CBE2CC276B1'
            Arguments = 'ALLUSERS=1 REBOOT=R'
            LogPath = "$vaConfigDataPath\Logs\VBA71_1033.log"
            DependsOn = "[xPackage]ReflectionProVBA71"
            IgnoreReboot = $true
        }
        xPackage MicrosoftCMTrace {
            Ensure = "Present"
            Name = "CMTrace"
            Path = ("{0}\DSC\Packages\Microsoft CM Trace\5.0.7804.1000 build 1.1\MSI\CMTrace.msi" -f $vaConfigDataPath)
            ProductId = "4BBB8DBB-FEFB-4DE5-82F5-F8F3D9856481"
            Arguments = 'ALLUSERS=1 REBOOT=R'
            LogPath = "$vaConfigDataPath\Logs\Microsoft_CMTrace_5.0.7804.1000.log"
            IgnoreReboot = $true
        }
        xPackage NotepadPlusPlus {
            Ensure = "Present"
            Name = "Notepad++ (64-bit x64)"
            Path = ("{0}\DSC\Packages\Notepad++\7.8.6\MSI\npp.7.8.6.Installer.x64.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = '/S /noUpdater'
            IgnoreReboot = $true
        }
        xPackage MicrosoftSilverlight {
            Ensure = "Present"
            Name = "Microsoft Silverlight"
            Path = ("{0}\DSC\Packages\Silverlight\5.1.50918.0\Silverlight_x64.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = '/q /noupdate'
            IgnoreReboot = $true
        }
        xPackage MicrosoftOffice365 {
            Ensure = "Present"
            Name = "Microsoft Office 365 ProPlus - en-us"
            Path = ("{0}\DSC\Packages\MicrosoftOffice365\Online\setup.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = ('/configure "{0}\DSC\Packages\MicrosoftOffice365\Online\VA_Deploy_FullBuild_64bit.xml"' -f $vaConfigDataPath)
            IgnoreReboot = $true
            DependsOn = "[Registry]OfficeDisableADAL"
        }
        xPackage InfoPath {
            Ensure = "Present"
            Name = "Microsoft InfoPath 2013"
            Path = ("{0}\DSC\Packages\Microsoft InfoPath 2013 for Citrix\Setup.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = ('/config "{0}\DSC\Packages\Microsoft InfoPath 2013 for Citrix\InfoPathConfig.xml"' -f $vaConfigDataPath)
            IgnoreReboot = $true
            DependsOn = "[xPackage]MicrosoftOffice365"
        }
        xPackage PublishMyeMailCerts {
            Ensure = "Present"
            Name = "Publish My eMail Certs"
            Path = ("{0}\DSC\Packages\Publish My eMail Certs\2.0 b1.1\MSI\PublishMyeMailCerts.msi" -f $vaConfigDataPath)
            ProductId = "BDDF21E2-9302-4ABD-8BD5-A636496D0D85"
            Arguments = 'ALLUSERS=1 REBOOT=R /qn'
            LogPath = "$vaConfigDataPath\Logs\VA_Publish_My_email_Certs_2.0.log"
            IgnoreReboot = $true
            DependsOn = "[xPackage]MicrosoftOffice365"
        }
        xPackage CofenseReporter {
            Ensure = "Present"
            Name = "Cofense Reporter"
            Path = ("{0}\DSC\Packages\Cofense Reporter\5.0.0 b1.1\MSI\Cofense Reporter for Outlook v5.0.0 - US Dept of Veterans Affairs (Neutral Instance) Reconfig.msi" -f $vaConfigDataPath)
            ProductId = "FB906DB1-27C4-4BDB-9AC6-F8210251032F"
            Arguments = ('TRANSFORMS="{0}\DSC\Packages\Cofense Reporter\5.0.0 b1.1\MSI\Cofense Reporter for Outlook v5.0.0 - US Dept of Veterans Affairs (Neutral Instance) Reconfig.Mst" ALLUSERS=1 REBOOT=R' -f $vaConfigDataPath)
            LogPath = "$vaConfigDataPath\Logs\Cofense_Reporter_5.0.0.log"
            IgnoreReboot = $true
            DependsOn = "[xPackage]MicrosoftOffice365"
        }
        xPackage VS2010ToolsForOffice {
            Ensure = "Present"
            Name = "Microsoft Visual Studio 2010 Tools for Office Runtime (x64)"
            Path = ("{0}\DSC\Packages\Redistributables\Visual Studio 2010 Tools for Office Runtime\10.0.60828\MSI\vstor_redist.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = ("/install /passive /norestart /log {0}\Logs\Microsoft_Visual_Studio_2010_Tools_for_Office_Runtime_10.0.60828.log" -f $vaConfigDataPath)
            IgnoreReboot = $true
            DependsOn = "[xPackage]MicrosoftOffice365"
        }
        xPackage MicrosoftOneDrive {
            Ensure = "Present"
            Name = "Microsoft OneDrive"
            Path = ("{0}\DSC\Packages\OneDrive\19.222.1110.0011\OneDriveSetup.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = "/allusers"
            IgnoreReboot = $true
            DependsOn = "[xPackage]MicrosoftOffice365"
        }
        # Auto start onedrive on remoteapp start
        Registry OneDriveRailRunOnce {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RailRunOnce'
            ValueName = 'OneDrive'
            ValueData = '"C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe" /background'
            ValueType = 'ExpandString'
        }
        Registry MicrosoftOneDriveRunOneDrive {
            Ensure = "Present"
            Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
            ValueName = "OneDrive"
            ValueData = "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe /background"
            ValueType = "String"
        }
        Registry MicrosoftOneDriveSilentAccountConfig {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
            ValueName = "SilentAccountConfig"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry OneDriveFilesOnDemandEnabled {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\OneDrive'
            ValueName = 'FilesOnDemandEnabled'
            ValueData = 1
            ValueType = 'DWORD'
        }
        xPackage PowerBIDesktop {
            Ensure = "Present"
            Name = "Microsoft PowerBI Desktop (x64)"
            Path = ("{0}\DSC\Packages\MicrosoftPowerBIDesktop\PBIDesktopSetup_x64.exe" -f $vaConfigDataPath)
            ProductId = ""
            Arguments = "-quiet -norestart ACCEPT_EULA=1 DISABLE_UPDATE_NOTIFICATION=1"
            LogPath = "$vaConfigDataPath\Logs\PBIDesktopSetup_x64.log"
            IgnoreReboot = $true
        }
        xPackage MicrosoftLAPSx64 {
            Ensure = "Present"
            Name = "Local Administrator Password Solution"
            Path = ("{0}\DSC\Packages\Microsoft Laps\6.0.1\x64\Laps.x64.msi" -f $vaConfigDataPath)
            ProductId = "F53D26E0-94E5-456F-AC72-C7676C9CE813"
            Arguments = ('TRANSFORMS="{0}\DSC\Packages\Microsoft Laps\6.0.1\x64\LAPS.x64.mst" CUSTOMADMINNAME=VA_SAA ALLUSERS=1 REBOOT=R' -f $vaConfigDataPath)
            LogPath = "$vaConfigDataPath\Logs\Microsoft_LAPS_6.0.1.0.log"
            IgnoreReboot = $true
        }
        xPackage MicrosoftSysinternalsBGInfo {
            Ensure = "Present"
            Name = "VA BGInfo"
            Path = ("{0}\DSC\Packages\Microsoft Sysinternals BGInfo\4.25.0.0\MSI\VA_BGInfo.msi" -f $vaConfigDataPath)
            ProductId = "C582BD56-79C6-465D-A473-9F72D24FBD8D"
            Arguments = 'ALLUSERS=1 REBOOT=R'
            LogPath = "$vaConfigDataPath\Logs\VA_BGInfo_4.25.0.0.log"
            IgnoreReboot = $true
        }
        ## FSLogix
        xPackage FsLogix {
            Ensure = "Present"
            Name = "Microsoft FsLogix Apps"
            Path = ("{0}\DSC\Packages\FSLogix_Apps_2.9.7486.53382\x64\Release\FSLogixAppsSetup.exe" -f $vaConfigDataPath)
            ProductId = ''
            Arguments = ("/norestart /quiet /log {0}\Logs\FSLogix_Apps_2.9.7486.53382.log" -f $vaConfigDataPath)
            IgnoreReboot = $true
        }
        Registry FsLogixProfileEnabled {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "Enabled"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixProfileVhdLocations {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VHDLocations"
            ValueData = $fsLogixVhdLocation
            ValueType = "MultiString"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixConcurrentUserSessions {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "ConcurrentUserSessions"
            ValueData = "0"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixDeleteLocalProfileWhenVHDShouldApply {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "DeleteLocalProfileWhenVHDShouldApply"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixLockedRetryCount {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "LockedRetryCount"
            ValueData = 3
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixPreventLoginWithFailure {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "PreventLoginWithFailure"
            ValueData = 1
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixPreventLoginWithTempProfile {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "PreventLoginWithTempProfile"
            ValueData = 1
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixVolumeType {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VolumeType"
            ValueData = "vhdx"
            ValueType = "string"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixVHDNamePattern {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VHDNamePattern"
            ValueData = "%username%_Profile"
            ValueType = "string"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixVHDNameMatch {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VHDNameMatch"
            ValueData = "%username%_Profile"
            ValueType = "string"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixFlipFlopProfileDirectoryName {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "FlipFlopProfileDirectoryName"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixProfileType {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "ProfileType"
            ValueData = "0"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixOfficeEnabled {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
            ValueName = "Enabled"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixOfficeCCDLocations {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
            ValueName = "VHDLocations"
            ValueData = $fsLogixVhdLocation
            ValueType = "MultiString"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixOfficeConcurrentUserSessions {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
            ValueName = "ConcurrentUserSessions"
            ValueData = "0"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixOfficeRemoveOrphanedOSTFilesOnLogoff {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
            ValueName = "RemoveOrphanedOSTFilesOnLogoff"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixOfficeLockedRetryCount {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\ODFC"
            ValueName = "LockedRetryCount"
            ValueData = 3
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixOfficePreventLoginWithFailure {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\ODFC"
            ValueName = "PreventLoginWithFailure"
            ValueData = 1
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixOfficePreventLoginWithTempProfile {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\ODFC"
            ValueName = "PreventLoginWithTempProfile"
            ValueData = 1
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixOfficeVHDNamePattern {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
            ValueName = "VHDNamePattern"
            ValueData = "%username%_Office"
            ValueType = "String"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixOfficeVHDNameMatch {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
            ValueName = "VHDNameMatch"
            ValueData = "%username%_Office"
            ValueType = "String"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixOfficeFlipFlopProfileDirectoryName {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
            ValueName = "FlipFlopProfileDirectoryName"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixOfficeVolumeType {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
            ValueName = "VolumeType"
            ValueData = "vhdx"
            ValueType = "String"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixOfficeIncludeTeams {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
            ValueName = "IncludeTeams"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Script FsLogixProfileGroupExclusion {
            DependsOn = '[xPackage]FsLogix'
            GetScript = { return @{'Result' = ''} }
            SetScript = { Add-LocalGroupMember -Group "FSLogix Profile Exclude List" -Member ("VA\VAOITWindowVirtualDesktop","VA\VAOITWindowsVirtualDesktop") -ErrorAction SilentlyContinue }
            TestScript = {
                If (Get-LocalGroup -Name "FSLogix Profile Exclude List") { Return $false }
                Else { Return $true }
            }
        }
        Script FsLogixOfficeGroupExclusion {
            DependsOn = '[xPackage]FsLogix'
            GetScript = { return @{'Result' = ''} }
            SetScript = { Add-LocalGroupMember -Group "FSLogix ODFC Exclude List" -Member ("VA\VAOITWindowVirtualDesktop","VA\VAOITWindowsVirtualDesktop") -ErrorAction SilentlyContinue }
            TestScript = {
                If (Get-LocalGroup -Name "FSLogix ODFC Exclude List") { Return $false }
                Else { Return $true }
            }
        }
        xPackage MicrosoftEdge {
            Ensure = "Present"
            Name = "Microsoft Edge"
            Path = ("{0}\DSC\Packages\MicrosoftEdge\81.0.416.68\MSI\MicrosoftEdgeEnterpriseX64.msi" -f $vaConfigDataPath)
            ProductId = "00DFE04E-EF8E-3A3F-9125-71EA36D0015B"
            Arguments = ('TRANSFORMS="{0}\DSC\Packages\MicrosoftEdge\81.0.416.68\MSI\MicrosoftEdgeEnterpriseX64.Mst" ALLUSERS=1 REBOOT=R' -f $vaConfigDataPath)
            LogPath = "$vaConfigDataPath\Logs\MicrosoftEdge_81.0.416.68.log"
            IgnoreReboot = $true
        }
        xPackage VABackupMySoftwareCertificate {
            Ensure = "Present"
            Name = "Backup My Software Certificate"
            Path = ("{0}\DSC\Packages\VA Backup My Software Certificate\1.0\MSI\BackupMySoftwareCert.msi" -f $vaConfigDataPath)
            ProductId = "39F676A3-ED5C-47A2-8A33-0CEE516ECC64"
            Arguments = 'ALLUSERS=1 REBOOT=R'
            LogPath = "$vaConfigDataPath\Logs\VA_BackupMySoftwareCertificate_1.0.log"
            IgnoreReboot = $true
        }
        xPackage GoogleChrome {
            Ensure = "Present"
            Name = "Google Chrome"
            Path = ("{0}\DSC\Packages\Google Chrome\81.0.4044.138\MSI\GoogleChromeStandaloneEnterprise64.msi" -f $vaConfigDataPath)
            ProductId = "C4EBFDFD-0C55-3E5F-A919-E3C54949024A"
            Arguments = 'ALLUSERS=1 REBOOT=R'
            LogPath = "$vaConfigDataPath\Logs\Google_Chrome_81.0.4044.138.log"
            IgnoreReboot = $true
        }
        Registry EnableTeamsWVD {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\\Microsoft\Teams"
            ValueName = "IsWVDEnvironment"
            ValueData = "1"
            ValueType = "DWORD"
        }
        xPackage MSTeams {
            Ensure = "Present"
            Name = "Teams Machine-Wide Installer"
            Path = ("{0}\DSC\Packages\Microsoft Teams\Teams_windows_x64.msi" -f $vaConfigDataPath)
            ProductId = "731F6BAA-A986-45A4-8936-7C3AAAAA760B"
            Arguments = "ALLUSER=1 ALLUSERS=1"
            LogPath = "$vaConfigDataPath\Logs\MicrosoftTeamsx64.log"
            IgnoreReboot = $true
        }
        Registry ATPGroup {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging"
            ValueName = "Group"
            ValueData = "WVD"
            ValueType = "String"
        }
        Registry VAGFEBrandingGovImg {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\VAVAL"
            ValueName = "GovImg"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry OEMManufacturer {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
            ValueName = "Manufacturer"
            ValueData = "Government Furnished Equipment"
            ValueType = "String"
        }
        Registry OEMLogo {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
            ValueName = "Logo"
            ValueData = "%PROGRAMDATA%\DeptOfVeteransAffairs\ESE-DT\OEMLogo\oemlogo.bmp"
            ValueType = "String"
        }
        Registry VAGFEBrandingGFE {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\VAVAL"
            ValueName = "GFE"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry WindowsUpdateAcceptTrustedPublisherCerts {
            Ensure = "Present"
            Key = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
            ValueName = "AcceptTrustedPublisherCerts"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry WindowsUpdateNoAutoUpdate {
            Ensure = "Present"
            Key = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "NoAutoUpdate"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry WindowsExplorerSpecialRoamingOverrideAllowed {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
            ValueName = "SpecialRoamingOverrideAllowed"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry WindowsTSfEnableTimeZoneRedirection {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            ValueName = "fEnableTimeZoneRedirection"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry WindowsAllowTelemetry {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            ValueName = "AllowTelemetry"
            ValueData = "3"
            ValueType = "DWORD"
        }
        Registry WindowsTSMaxMonitors {
            Ensure = "Present"
            Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            ValueName = "MaxMonitors"
            ValueData = "4"
            ValueType = "DWORD"
        }
        Registry WindowsTSMaxXResolution {
            Ensure = "Present"
            Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            ValueName = "MaxXResolution"
            ValueData = "5120"
            ValueType = "DWORD"
        }
        Registry WindowsTSMaxYResolution {
            Ensure = "Present"
            Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            ValueName = "MaxYResolution"
            ValueData = "2880"
            ValueType = "DWORD"
        }
        Registry WindowsTSMaxMonitorssxs {
            Ensure = "Present"
            Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs"
            ValueName = "MaxMonitors"
            ValueData = "4"
            ValueType = "DWORD"
        }
        Registry WindowsTSMaxXResolutionsxs {
            Ensure = "Present"
            Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs"
            ValueName = "MaxXResolution"
            ValueData = "5120"
            ValueType = "DWORD"
        }
        Registry WindowsTSMaxYResolutionsxs {
            Ensure = "Present"
            Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs"
            ValueName = "MaxYResolution"
            ValueData = "2880"
            ValueType = "DWORD"
        }
        Registry OfficeDisableADAL {
            Ensure = "Present"
            Key = "HKEY_USERS\.DEFAULT\Software\Microsoft\Office\16.0\Common\Identity"
            ValueName = "DisableADALatopWAMOverride"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry OfficeSharedComputerLicense {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
            ValueName = "SharedComputerLicensing"
            ValueData = "1"
            ValueType = "String"
        }
        Registry OfficeHideUpdateNotifications {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate"
            ValueName = "hideupdatenotifications"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry OfficeDisableUpdates {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate"
            ValueName = "hideenabledisableupdates"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry SchUseStrongCrypto {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
            ValueName = "SchUseStrongCrypto"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry SchUseStrongCryptoWOW6432 {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
            ValueName = "SchUseStrongCrypto"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry SchUseStrongCryptoNet20 {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727"
            ValueName = "SchUseStrongCrypto"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry SchUseStrongCryptoNet20WOW6432 {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"
            ValueName = "SchUseStrongCrypto"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry IEExceptionHandlerHardening {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
            ValueName = "iexplore.exe"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry IEExceptionHandlerHarderingWOW6432 {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
            ValueName = "iexplore.exe"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry CredentialPrompt {
            Ensure = "Present"
            Key = "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters"
            ValueName = "AuthForwardServerList"
            ValueData = "*.va.gov"
            ValueType = "MultiString"
        }
        Registry SyncForegroundPolicy {
            Ensure = "Present"
            Key = "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon"
            ValueName = "SyncForegroundPolicy"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Script StartLayout {
            SetScript = {
                Import-StartLayout -LayoutPath "$using:vaConfigDataPath\DSC\Packages\Win10_StartTaskbar\StartTaskbar.xml" -MountPath "C:\"
                New-Item -Path "C:\ProgramData\DeptOfVeteransAffairs\" -Name "StartLayoutSet.txt" -ItemType "file"
            }
            GetScript = {
                @{ Result = (Test-Path 'C:\ProgramData\DeptOfVeteransAffairs\StartLayoutSet.txt') }
            }
            TestScript = {
                return (Test-Path 'C:\ProgramData\DeptOfVeteransAffairs\StartLayoutSet.txt')
            }
        }
        Script GemaltoSafeNetMiniDriver {
            SetScript = {
                pnputil.exe -i -a "C:\Program Files\Gemalto\SafeNet Minidriver\*.inf"
                rundll32.exe syssetup,SetupInfObjectInstallAction DefaultInstall 128 C:\Program Files\Gemalto\SafeNet Minidriver\SafeNet.Minidriver.inf
            }
            GetScript = {
                @{ Result = (pnputil.exe /enum-drivers | Where-Object{$_ -like "*safenet.minidriver.inf*"}) }
            }
            TestScript = {
                if (pnputil.exe /enum-drivers | Where-Object{$_ -like "*safenet.minidriver.inf*"}) { Return $true }
                else { Return $false }
            }
            DependsOn = '[xPackage]GemaltoSafeNetMiniDriverx64'
        }
        Script ATPOnboarding {
            TestScript = {
                if((get-service "sense").Status -eq "Stopped") { return $false }
                else { return $true }
            }
            GetScript = {
                @{ Result = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "OnboardingInfo") }
            }
            SetScript = { . "$using:vaConfigDatapath\DSC\Packages\MDATP\Onboard-NonPersistentMachine.ps1" }
            DependsOn = "[Registry]ATPGroup"
        }
        xPackage PolicyPakClientSideExtension {
            Ensure = "Present"
            Name = "PolicyPak Client-Side Extension"
            Path = ("{0}\DSC\Packages\PolicyPak Client-Side Extension\20.2.2362\MSI\PolicyPakClient-SideExtensionx64.msi" -f $vaConfigDataPath)
            ProductId = "F0DE6825-3FEA-4F2E-B33A-84C5A07B96CE"
            Arguments = ('TRANSFORMS="{0}\DSC\Packages\PolicyPak Client-Side Extension\20.2.2362\MSI\PolicyPakClient-SideExtensionx64.Mst" ALLUSERS=1 REBOOT=R' -f $vaConfigDataPath)
            LogPath = "$vaConfigDataPath\Logs\PolicyPak_ClientSide_Extension_20.2.2362.log"
            IgnoreReboot = $true
        }
        if ($DeploymentType -eq "GFE") {
            Registry ActivIdAllowServiceAccessWithNoReaders {
                Ensure = "Present"
                Key = "HKLM:\Software\Microsoft\Cryptography\Calais\"
                ValueName = "AllowServiceAccessWithNoReaders"
                ValueData = "1"
                ValueType = "DWORD"
            }
            Registry ActivIdAllowServiceAccessWithNoReadersWOW6432 {
                Ensure = "Present"
                Key = "HKLM:\Software\WOW6432Node\Microsoft\Cryptography\Calais"
                ValueName = "AllowServiceAccessWithNoReaders"
                ValueData = "1"
                ValueType = "DWORD"
                DependsOn = "[Registry]ActivIdAllowServiceAccessWithNoReaders"
            }
            Script RebootBeforeActivClient {
                TestScript = { return (Test-Path 'C:\ProgramData\DeptOfVeteransAffairs\RebootBeforeActivClient.txt') }
                SetScript = {
                    New-Item -Path "C:\ProgramData\DeptOfVeteransAffairs\" -Name "RebootBeforeActivClient.txt" -ItemType "file"
                    $global:DSCMachineStatus = 1
                }
                GetScript = {
                    @{ Result = (Test-Path 'C:\ProgramData\DeptOfVeteransAffairs\RebootBeforeActivClient.txt') }
                }
                DependsOn = "[Registry]ActivIdAllowServiceAccessWithNoReadersWOW6432"
            }
            xPackage ActivIDActivClient {
                Ensure = "Present"
                Name = "ActivID ActivClient x64"
                Path = ("{0}\DSC\Packages\HID Global ActivID ActivClient x64\7.1.0.213 b.1.2\MSI\ActivID ActivClient x64 7.1.msi" -f $vaConfigDataPath)
                ProductId = "BCE4067B-9B40-4316-9235-6A1EEAD55622"
                Arguments = ('TRANSFORMS="{0}\DSC\Packages\HID Global ActivID ActivClient x64\7.1.0.213 b.1.2\MSI\ActivID ActivClient x64 7.1.Mst" AddLocal=Help,ACOMX,ActivClient,BSI,Common,Core,Digital,MiniDriver,PKCS,PIV,Troubleshooting,UserConsole,SettingsManagement ALLUSERS=1 /forcerestart' -f $vaConfigDataPath)
                LogPath = "$vaConfigDataPath\Logs\HID_Global_ActivID_ActivClient_x64_7.1.0.213.log"
                DependsOn = "[Script]RebootBeforeActivClient"
                IgnoreReboot = $false

            }
            xPackage ActivClientCMSDLLUpdate {
                Ensure = "Present"
                Name = "ActivClient 7.1.0.213 CMS DLL Update"
                Path = ("{0}\DSC\Packages\HID Global ActivID ActivClient x64\ActivClient 7.1.0.213 CMS DLL Update\1.0\MSI\ActivClientDLL.msi" -f $vaConfigDataPath)
                ProductId = "356A5743-D62D-46B7-902D-779EBF555B1A"
                Arguments = 'ALLUSERS=1 REBOOT=R'
                LogPath = "$vaConfigDataPath\Logs\VA_ActivClient_7.1.0.213_CMS_DLL_Update_1.0.log"
                DependsOn = '[Script]ActivClientMSP'
                IgnoreReboot = $true
            }
            xPackage ActivClientCPRSCryptoUpdate {
                Ensure = "Present"
                Name = "CPRS Crypto Update"
                Path = ("{0}\DSC\Packages\HID Global ActivID ActivClient x64\CPRS Crypto Update\1.3\MSI\CPRS Crypto Update.msi" -f $vaConfigDataPath)
                ProductId = "B9B86D44-BE8B-42F3-849D-A6C75C0871F4"
                Arguments = 'ALLUSERS=1 REBOOT=R'
                LogPath = "$vaConfigDataPath\Logs\VA_CPRS_Crypto_Update_1.3.log"
                DependsOn = '[xPackage]ActivClientCMSDLLUpdate'
                IgnoreReboot = $true
            }
            Script ActivClientMSP {
                TestScript = {
                    if ((Get-Item "C:\Program Files\HID Global\ActivClient\ac.activclient.gui.scagent.exe").VersionInfo.FileVersion -eq "7.1.0.151") { return $false }
                    else { return $true }
                }
                GetScript = {
                    @{ Result = ((Get-Item "C:\Program Files\HID Global\ActivClient\ac.activclient.gui.scagent.exe").VersionInfo.FileVersion) }
                }
                SetScript = { Start-Process -FilePath "msiexec.exe" -ArgumentList "/update `"$using:vaConfigDataPath\DSC\Packages\HID Global ActivID ActivClient x64\7.1.0.213 b.1.2\MSI\AC_7.1.0.213_FIXS1807009_x64.msp`" /quiet REBOOT=R" }
                DependsOn = "[xPackage]ActivIDActivClient"
            }
        }
        Script RebootPostInstall {
            TestScript = { return (Test-Path 'C:\ProgramData\DeptOfVeteransAffairs\RebootPostInstall.txt') }
            SetScript = {
                New-Item -Path "C:\ProgramData\DeptOfVeteransAffairs\" -Name "RebootPostInstall.txt" -ItemType "file"
                $global:DSCMachineStatus = 1
            }
            GetScript = {
                @{ Result = (Test-Path 'C:\ProgramData\DeptOfVeteransAffairs\RebootPostInstall.txt') }
            }
            DependsOn = "[Script]ATPOnboarding"
        }
    }
}
#WvdWin10Config -OutputPath "C:\Temp\MOF"
#Start-Sleep -Seconds 3
#Set-DscLocalConfigurationManager -Path "C:\Temp\MOF"-Verbose
#Start-Sleep -Seconds 3
#Start-DscConfiguration -Path "C:\Temp\MOF" -Force -Verbose -Wait