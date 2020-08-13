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
    Start-BitsTransfer -Source "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration_7-20-2020.zip" -Destination ($env:TEMP + "\wvdConfiguration.zip")
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
                If ($Members -contains "VA\VAOITWindowsVirtualDesktop") { Return $true }
                Else { Return $false }
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
            ValueName = "CCDLocations"
            ValueData = ("type=smb,connectionString={0}" -f $fsLogixVhdLocation)
            ValueType = "MultiString"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixConcurrentUserSessions {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "ConcurrentUserSessions"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }Registry FsLogixProfileSize {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "SizeInMBs"
            ValueData = "30000"
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
            ValueData = "3"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
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
        Script RebootPostInstall {
            TestScript = { return (Test-Path 'C:\ProgramData\DeptOfVeteransAffairs\RebootPostInstall.txt') }
            SetScript = {
                New-Item -Path "C:\ProgramData\DeptOfVeteransAffairs\" -Name "RebootPostInstall.txt" -ItemType "file"
                $global:DSCMachineStatus = 1
            }
            GetScript = {
                @{ Result = (Test-Path 'C:\ProgramData\DeptOfVeteransAffairs\RebootPostInstall.txt') }
            }
        }
    }
}