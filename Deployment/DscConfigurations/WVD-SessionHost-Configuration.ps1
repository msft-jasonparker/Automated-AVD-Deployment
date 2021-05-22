Configuration Wvd-SessionHost-Configuration {
    # DSC Modules
    Import-DSCResource -ModuleName "PSDesiredStateConfiguration"
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DSCResource -ModuleName "xPSDesiredStateConfiguration" -ModuleVersion 9.1.0

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
        # WVD Packages
        Script WVDSoftwarePackage {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = {
                If (Test-Path -Path ("{0}\Temp\wvd_packages.zip" -f $using:Node.DscSourcePath)) {
                    $currentZip = Get-ChildItem -Path ("{0}\Temp\wvd_packages.zip" -f $using:Node.DscSourcePath)
                    return ((Get-Date).ToUniversalTime -ge $currentZip.CreationTimeUtc)
                }
                else { return $false }
            }
            SetScript  = {
                If (Test-Path -Path ("{0}\wvd_packages.zip" -f $using:WvdData.WvdArtifactLocation)) {
                    (New-Object System.Net.WebClient).DownloadFile(("{0}\wvd_packages.zip" -f $using:WvdData.WvdArtifactLocation), ("{0}\Temp\wvd_packages.zip" -f $using:Node.DscSourcePath))
                    If (Test-Path -Path ("{0}\Temp\wvd_packages.zip" -f $using:Node.DscSourcePath)) { Expand-Archive -Path ("{0}\Temp\wvd_packages.zip" -f $using:Node.DscSourcePath) -DestinationPath ("{0}\DSC" -f $using:Node.DscSourcePath) -Force }
                }
                Else {
                    Write-Warning ("Path not found: {0}\wvd_packages.zip" -f $using:WvdData.WvdArtifactLocation)
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
            SetScript  = {
                . ($using:Node.DscSourcePath + "\WVD\Functions.ps1")
                try { & ("{0}\WVD\Script-AddRdshServer.ps1" -f $using:Node.DscSourcePath) -HostPoolName $using:WvdData.HostPoolName -RegistrationInfoToken $using:WvdData.RegistrationToken }
                catch {
                    $ErrMsg = $PSItem | Format-List -Force | Out-String
                    Write-Log -Err $ErrMsg
                    throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallServer SetScript: $ErrMsg", $PSItem.Exception)
                }
            }
            TestScript = {
                If (Test-Path -Path ($using:Node.DscSourcePath + "\WVD\Functions.ps1")) {
                    . ($using:Node.DscSourcePath + "\WVD\Functions.ps1")
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
        }
        # VDI/WVD Optimization Script
        Script VDI_Optimize {
            TestScript = {
                if ((Get-ScheduledTask MapsToastTask).State -eq "Disabled") { return $true }
                else { return $false }
            }
            SetScript  = {
                try { & ("{0}\DSC\Packages\VDI-Optimize\Win10_VirtualDesktop_Optimize.ps1" -f $using:Node.DscSourcePath) -Restart -Verbose }
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
        xPackage VisualStudioCode {
            Ensure       = "Present"
            Name         = "Microsoft Visual Studio Code"
            Path         = ("{0}\DSC\Packages\Visual-Studio-Code\1.53.2\VSCodeSetup.exe" -f $Node.DscSourcePath)
            ProductId    = ''
            Arguments    = ('/VERYSILENT /NORESTART /MERGETASKS=!runcode /LOG="{0}\Logs\VSCodeSetup.log"' -f $Node.DscSourcePath)
            IgnoreReboot = $true
            DependsOn    = "[Script]WVDSoftwarePackage"
        }
        xPackage Git {
            Ensure       = "Present"
            Name         = "Git version 2.30.1"
            Path         = ("{0}\DSC\Packages\Git\2.30.1\Git.exe" -f $Node.DscSourcePath)
            ProductId    = ''
            Arguments    = ('/VERYSILENT /NORESTART /LOG="{0}\Logs\Git.log"' -f $Node.DscSourcePath)
            IgnoreReboot = $true
            DependsOn    = "[Script]WVDSoftwarePackage"
        }
        xPackage NotepadPlusPlus {
            Ensure       = "Present"
            Name         = "Notepad++ (64-bit x64)"
            Path         = ("{0}\DSC\Packages\Notepad++\7.8.8\npp.exe" -f $Node.DscSourcePath)
            ProductId    = ''
            Arguments    = '/S /noUpdater'
            LogPath      = ("{0}\Logs\npp.log" -f $Node.DscSourcePath)
            IgnoreReboot = $true
            DependsOn    = "[Script]WVDSoftwarePackage"
        }
        # FSLogix
        xPackage FsLogix {
            Ensure       = "Present"
            Name         = "Microsoft FsLogix Apps"
            Path         = ("{0}\DSC\Packages\FSLogix\2.9.7654.46150\FSLogixAppsSetup.exe" -f $Node.DscSourcePath)
            ProductId    = ''
            Arguments    = ("/norestart /quiet /log {0}\Logs\FSLogixAppsSetup.log" -f $Node.DscSourcePath)
            IgnoreReboot = $true
            DependsOn    = "[Script]WVDSoftwarePackage"
        }
        Registry FsLogixProfileEnabled {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "Enabled"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixProfileVhdLocations {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VHDLocations"
            ValueData = $WvdData.FsLogixVhdLocation
            ValueType = "MultiString"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixConcurrentUserSessions {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "ConcurrentUserSessions"
            ValueData = "0"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixProfileSize {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "SizeInMBs"
            ValueData = "30000"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixDeleteLocalProfileWhenVHDShouldApply {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "DeleteLocalProfileWhenVHDShouldApply"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixLockedRetryCount {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "LockedRetryCount"
            ValueData = 3
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixVolumeType {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VolumeType"
            ValueData = "vhdx"
            ValueType = "string"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixVHDNamePattern {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VHDNamePattern"
            ValueData = "%username%_Profile"
            ValueType = "string"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixVHDNameMatch {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VHDNameMatch"
            ValueData = "%username%_Profile"
            ValueType = "string"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixFlipFlopProfileDirectoryName {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "FlipFlopProfileDirectoryName"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
        }
        Registry FsLogixCleanupInvalidSessions {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Apps"
            ValueName = "CleanupInvalidSessions"
            ValueData = "1"
            ValueType = "DWORD"
            DependsOn = '[xPackage]FsLogix'
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