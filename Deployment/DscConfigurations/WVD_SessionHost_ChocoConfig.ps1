Configuration Wvd_SessionHost_ChocoConfig {
    # DSC Modules
    Import-DSCResource -ModuleName "PSDesiredStateConfiguration"
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName cChoco
    Import-DSCResource -ModuleName "xPSDesiredStateConfiguration"

    Node $AllNodes.Where{ $true }.NodeName {
        $WvdData = $ConfigurationData.WvdData

        # LCM Settings
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }
        # PowerShell Execution Policy
        PowerShellExecutionPolicy ExecutionPolicyLocalMachine {
            ExecutionPolicyScope = 'LocalMachine'
            ExecutionPolicy      = 'Bypass'
        }
        # Timezone
        TimeZone SetLocalTimeZone {
            IsSingleInstance = 'Yes'
            TimeZone         = 'US Mountain Standard Time'
        }
        # Ensure directory for packages exists
        File CreatePackageDirectory {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = ("{0}\DSC\Packages" -f $Node.DscSourcePath)
        }
        #Create directory for MSI logs
        File CreateLogDirectory {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = ("{0}\Logs" -f $Node.DscSourcePath)
        }
        # Create directory for temp files
        File CreateTempDirectory {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = ("{0}\Temp" -f $Node.DscSourcePath)
        }
        # WVD Agent Download
        Script WVDAgentDownload {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = { Test-Path -Path ("{0}\WVD\Functions.ps1" -f $using:Node.DscSourcePath) }
            SetScript  = {
                (New-Object System.Net.WebClient).DownloadFile($using:WvdData.WvdAgentInstallUri, ("{0}\Temp\wvd_agent_installer.zip" -f $using:Node.DscSourcePath))
                If (Test-Path -Path ("{0}\Temp\wvd_agent_installer.zip" -f $using:Node.DscSourcePath)) {
                    Expand-Archive -Path ("{0}\Temp\wvd_agent_installer.zip" -f $using:Node.DscSourcePath) -DestinationPath ("{0}\WVD" -f $using:Node.DscSourcePath) -Force
                    If (Test-Path -Path ("{0}\WVD\Functions.ps1" -f $using:Node.DscSourcePath)) {
                        . ("{0}\WVD\Functions.ps1" -f $using:Node.DscSourcePath)
                    }
                    Else { Write-Warning ("Failed to expand zip file: wvd_agent_installer.zip") }
                }
                Else { Write-Warning ("Failed to download file: wvd_agent_installer.zip to {0}\Temp\wvd_agent_installer.zip" -f $using:Node.DscSourcePath) }
            }
        }
        # Domain Join Sleep
        Script DomainJoinSleep {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = {
                If (Test-Path ("{0}\DomainJoinSleep.txt" -f $using:Node.DscSourcePath)) { Return $true }
                Else { Return $false }
            }
            SetScript  = {
                New-Item -Path $using:Node.DscSourcePath -Name "DomainJoinSleep.txt" -ItemType "file"
                Start-Sleep -Seconds 60
            }
        }
        # Chocolatey Install
        cChocoInstaller ChocolateyInstall {
            InstallDir = ("{0}\choco" -f $Node.DscSourcePath)
        }
        # WVD Packages
        Script WVDSoftwarePackage {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = {
                If (Test-Path -Path ("{0}\Temp\wvd_packages.zip" -f $using:Node.DscSourcePath)) {
                    $currentZip = Get-ChildItem -Path ("{0}\Temp\wvd_packages.zip" -f $using:Node.DscSourcePath)
                    return ((Get-Date).ToUniversalTime() -ge $currentZip.CreationTimeUtc)
                }
                else { return $false }
            }
            SetScript  = {
                If (Test-Path -Path ("{0}\wvd_packages.zip" -f $using:Node.WvdArtifactLocation)) {
                    (New-Object System.Net.WebClient).DownloadFile(("{0}\wvd_packages.zip" -f $using:Node.WvdArtifactLocation), ("{0}\Temp\wvd_packages.zip" -f $using:Node.DscSourcePath))
                    If (Test-Path -Path ("{0}\Temp\wvd_packages.zip" -f $using:Node.DscSourcePath)) { Expand-Archive -Path ("{0}\Temp\wvd_packages.zip" -f $using:Node.DscSourcePath) -DestinationPath ("{0}\DSC" -f $using:Node.DscSourcePath) -Force }
                }
                Else {
                    Write-Warning ("Path not found: {0}\wvd_packages.zip" -f $using:Node.WvdArtifactLocation)
                    If (Test-Path -Path ("{0}\MissingWVDPackageReboot.txt" -f $using:Node.DscSourcePath)) {
                        Throw [System.Exception]::new("WVD Packages zip not found post 2nd reboot", "MissingWVDPackageReboot")
                    }
                    Else {
                        New-Item -Path $using:Node.DscSourcePath -Name "MissingWVDPackageReboot.txt" -ItemType "file"
                        $global:DSCMachineStatus = 1
                    }
                }
            }
            DependsOn  = "[Script]DomainJoinSleep"
        }
        # Powershell
        ## Providers
        ### Nuget Provider
        Script PowerShellNugetProvider {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = {
                $remoteNuget = Find-PackageProvider Nuget
                $localNuget = Get-PackageProvider Nuget
                Return ($localNuget.Version.ToString() -ge $remoteNuget.Version)
            }
            SetScript  = { Find-PackageProvider Nuget | Install-PackageProvider -Scope AllUsers -Force }
        }
        ### PowerShellGet Provider
        Script PowerShellGetProvider {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = {
                $remotePSGet = Find-PackageProvider PowerShellGet
                $localPSGet = Get-PackageProvider PowerShellGet
                Return ($localPSGet.Version.ToString() -ge $remotePSGet.Version)
            }
            SetScript  = { Find-PackageProvider PowerShellGet | Install-PackageProvider -Scope AllUsers -Force }
        }
        ## Modules
        ### Az Module
        Script AzPowerShellModule {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = {
                $azModuleCheck = Get-InstalledModule Az -ErrorAction SilentlyContinue
                If ($azModuleCheck) {
                    $azModule = Find-Module Az
                    Return ($azModule.Version -ge $azModuleCheck.Version)
                }
                Else { Return $false }
            }
            SetScript  = { Find-Module Az | Install-Module -Force }
        }
        ### AzureAD Module
        Script AzureADPowerShellModule {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = {
                $azureADModuleCheck = Get-InstalledModule AzureAD -ErrorAction SilentlyContinue
                If ($azureADModuleCheck) {
                    $azureADModule = Find-Module AzureAD
                    Return ($azureADModule.Version -ge $azureADModuleCheck.Version)
                }
                Else { Return $false }
            }
            SetScript  = { Find-Module AzureAD | Install-Module -Force }
        }
        ### SharePoint Online Module
        Script SPOPowerShellModule {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = {
                $spoModuleCheck = Get-InstalledModule "Microsoft.Online.SharePoint.PowerShell" -ErrorAction SilentlyContinue
                If ($spoModuleCheck) {
                    $spoModule = Find-Module "Microsoft.Online.SharePoint.PowerShell"
                    Return ($spoModule.Version -ge $spoModuleCheck.Version)
                }
                Else { Return $false }
            }
            SetScript  = { Find-Module "Microsoft.Online.SharePoint.PowerShell" | Install-Module -Force }
        }
        ### Exchange Online Module
        Script EXOPowerShellModule {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = {
                $exoModuleCheck = Get-InstalledModule ExchangeOnlineManagement -ErrorAction SilentlyContinue
                If ($exoModuleCheck) {
                    $exoModule = Find-Module ExchangeOnlineManagement
                    Return ($exoModule.Version -ge $exoModuleCheck.Version)
                }
                Else { Return $false }
            }
            SetScript  = { Find-Module ExchangeOnlineManagement | Install-Module -Force }
        }
        ### SQL Module
        Script SQLPowerShellModule {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = {
                $sqlModuleCheck = Get-InstalledModule SqlServer -ErrorAction SilentlyContinue
                If ($sqlModuleCheck) {
                    $sqlModule = Find-Module SqlServer
                    Return ($sqlModule.Version -ge $sqlModuleCheck.Version)
                }
                Else { Return $false }
            }
            SetScript  = { Find-Module SqlServer | Install-Module -Force }
        }
        # WVD HostPool Registration
        Script WVDAgentInstall {
            DependsOn  = "[Script]WVDAgentDownload"
            GetScript  = { return @{'Result' = '' } }
            TestScript = {
                If (Test-Path -Path ($using:Node.DscSourcePath + "\WVD\Functions.ps1")) {
                    try {
                        If (Test-path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent") { Return $true }
                        Else { Return $false }
                    }
                    catch {
                        $ErrMsg = $PSItem | Format-List -Force | Out-String
                        Write-Log -Err $ErrMsg
                        throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallServer TestScript: $ErrMsg", $PSItem.Exception)
                    }
                }
                Else {
                    $ErrMsg = $PSItem | Format-List -Force | Out-String
                    throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallServer TestScript: $ErrMsg", $PSItem.Exception)
                }
            }
            SetScript  = {
                . ($using:Node.DscSourcePath + "\WVD\Functions.ps1")
                try { & ("{0}\WVD\Script-AddRdshServer.ps1" -f $using:Node.DscSourcePath) -HostPoolName $using:Node.NodeName -RegistrationInfoToken $using:Node.RegistrationToken }
                catch {
                    $ErrMsg = $PSItem | Format-List -Force | Out-String
                    Write-Log -Err $ErrMsg
                    throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallServer SetScript: $ErrMsg", $PSItem.Exception)
                }
            }
        }
        # VDI/WVD Optimization Script
        Script VDI_Optimize {
            TestScript = {
                if ((Get-ScheduledTask MapsToastTask).State -eq "Disabled") { return $true }
                else { return $false }
            }
            SetScript  = {
                try { & ("{0}\DSC\Packages\VDI-Optimize\Win10_VirtualDesktop_Optimize.ps1" -f $using:Node.DscSourcePath) -Verbose }
                catch {
                    $ErrMsg = $PSItem | Format-List -Force | Out-String
                    throw [System.Exception]::new(("Error running VDI Script Resource: {0}" -f $ErrMsg), $PSItem.Exception)
                }
            }
            GetScript  = {
                @{ Result = ((Get-ScheduledTask MapsToastTask).State) }
            }
            DependsOn  = "[Script]WVDSoftwarePackage"
        }
        # Software Packages
        cChocoPackageInstaller fslogix {
            Name      = 'fslogix'
            Ensure    = 'Present'
            Version   = '2.9.7654.4615001'
            DependsOn = "[cChocoInstaller]ChocolateyInstall"
        }
        cChocoPackageInstaller VisualStudioCode {
            Name      = 'vscode'
            Ensure    = 'Present'
            Version   = '1.53.2'
            DependsOn = '[cChocoInstaller]ChocolateyInstall'
        }
        cChocoPackageInstaller GitSourceControl {
            Name      = 'git'
            Ensure    = 'Present'
            Version   = '2.30.1'
            DependsOn = '[cChocoInstaller]ChocolateyInstall'
        }
        cChocoPackageInstaller NotepadPlusPlus {
            Name      = 'notepadplusplus'
            Ensure    = 'Present'
            Version   = '7.9.3'
            DependsOn = '[cChocoInstaller]ChocolateyInstall'
        }
        cChocoPackageInstaller MicrosoftEdge {
            Name      = 'microsoft-edge'
            Ensure    = 'Present'
            Version   = '88.0.705.68'
            DependsOn = '[cChocoInstaller]ChocolateyInstall'
        }
        cChocoPackageInstaller GoogleChrome {
            Name      = 'googlechrome'
            Ensure    = 'Present'
            Version   = '88.0.4324.182'
            DependsOn = '[cChocoInstaller]ChocolateyInstall'
        }
        cChocoPackageInstaller 7Zip {
            Name      = '7zip'
            Ensure    = 'Present'
            Version   = '19.0'
            DependsOn = '[cChocoInstaller]ChocolateyInstall'
        }
        cChocoPackageInstaller AdobeReader {
            Name      = 'adobereader'
            Ensure    = 'Present'
            Version   = '2021.001.20138'
            DependsOn = '[cChocoInstaller]ChocolateyInstall'
        }
        # Registry Settings
        Registry FsLogixProfileEnabled {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "Enabled"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[cChocoPackageInstaller]fslogix'
        }
        Registry FsLogixProfileVhdLocations {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VHDLocations"
            ValueData = $Node.WvdFsLogixVhdLocation
            ValueType = "MultiString"
            DependsOn = '[cChocoPackageInstaller]fslogix'
        }
        Registry FsLogixConcurrentUserSessions {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "ConcurrentUserSessions"
            ValueData = "0"
            ValueType = "DWORD"
            DependsOn = '[cChocoPackageInstaller]fslogix'
        }
        Registry FsLogixProfileSize {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "SizeInMBs"
            ValueData = "30000"
            ValueType = "DWORD"
            DependsOn = '[cChocoPackageInstaller]fslogix'
        }
        Registry FsLogixDeleteLocalProfileWhenVHDShouldApply {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "DeleteLocalProfileWhenVHDShouldApply"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[cChocoPackageInstaller]fslogix'
        }
        Registry FsLogixLockedRetryCount {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "LockedRetryCount"
            ValueData = 3
            ValueType = "DWORD"
            DependsOn = '[cChocoPackageInstaller]fslogix'
        }
        Registry FsLogixVolumeType {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VolumeType"
            ValueData = "vhdx"
            ValueType = "string"
            DependsOn = '[cChocoPackageInstaller]fslogix'
        }
        Registry FsLogixVHDNamePattern {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VHDNamePattern"
            ValueData = "%username%_Profile"
            ValueType = "string"
            DependsOn = '[cChocoPackageInstaller]fslogix'
        }
        Registry FsLogixVHDNameMatch {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VHDNameMatch"
            ValueData = "%username%_Profile"
            ValueType = "string"
            DependsOn = '[cChocoPackageInstaller]fslogix'
        }
        Registry FsLogixFlipFlopProfileDirectoryName {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "FlipFlopProfileDirectoryName"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[cChocoPackageInstaller]fslogix'
        }
        Registry FsLogixCleanupInvalidSessions {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Apps"
            ValueName = "CleanupInvalidSessions"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[cChocoPackageInstaller]fslogix'
        }
        Script RebootPostInstall {
            GetScript  = { return @{'Result' = '' } }
            TestScript = {
                If (Test-Path ("{0}\RebootPostInstall.txt" -f $using:Node.DscSourcePath)) { Return $true }
                Else { Return $false }
            }
            SetScript  = {
                New-Item -Path $using:Node.DscSourcePath -Name "RebootPostInstall.txt" -ItemType "file"
                $global:DSCMachineStatus = 1
            }
        }
    }
}