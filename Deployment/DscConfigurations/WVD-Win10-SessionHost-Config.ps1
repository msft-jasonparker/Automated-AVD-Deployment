Configuration WvdSessionHostConfig
{
    Param (
        [string]$HostPoolName,
        [string]$RegistrationInfoToken,
        [string]$wvdDscConfigZipUrl,
        [string]$DeploymentFunction,
        [string]$DeploymentType,
        [string]$fsLogixVhdLocation
    )
    Set-ExecutionPolicy "RemoteSigned" -Scope Process -Confirm:$false
    Set-ExecutionPolicy "RemoteSigned" -Scope CurrentUser -Confirm:$false

    # DSC Modules
    Import-DSCResource -ModuleName "PSDesiredStateConfiguration"
    Import-DSCResource -ModuleName "xPSDesiredStateConfiguration" -ModuleVersion 9.1.0
    Import-DscResource -ModuleName "CertificateDsc" -ModuleVersion 5.0.0
    Import-DscResource -ModuleName "ComputerManagementDsc" -ModuleVersion 8.4.0
    Import-Module -Name BitsTransfer -force

    $wvdConfigDataPath = "C:\ProgramData\WVD-Automated-Deployment"
    Start-BitsTransfer -Source $wvdDscConfigZipUrl -Destination ($env:TEMP + "\wvdConfiguration.zip")
    If (Test-Path -Path ($env:TEMP + "\wvdConfiguration.zip")) { Expand-Archive -Path ($env:TEMP + "\wvdConfiguration.zip") -DestinationPath ($wvdConfigDataPath + "\WVD") -Force}
    
    . ($wvdConfigDataPath + "\WVD\Functions.ps1")

    Node localhost {
        # LCM Settings
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }
        ## Local Administrators
        Script LocalAdministratorsGroup {
            GetScript = { return @{'Result' = ''} }
            SetScript = { Add-LocalGroupMember -Group "Administrators" -Member "<group-name-to-be-added-to-local-admins>" -ErrorAction SilentlyContinue }
            TestScript = {
                $Members = Get-LocalGroupMember -Group "Administrators" | Foreach-Object {$_.Name}
                If ($Members -contains "<group-name-to-be-added-to-local-admins>") { Return $true }
                Else { Return $false }
            }
        }
        ## Domain Join Sleep
        Script DomainJoinSleep {
            TestScript = { return (Test-Path ("{0}\DomainJoinSleep.txt" -f $wvdConfigDataPath)) }
            SetScript = {
                New-Item -Path $using:wvdConfigDataPath -Name "DomainJoinSleep.txt" -ItemType "file"
                Start-Sleep -Seconds 60
            }
            GetScript = {
                @{ Result = (Test-Path (Test-Path ("{0}\DomainJoinSleep.txt" -f $wvdConfigDataPath)) }
            }
        }
        ## Local Administrators
        Script LocalAdministratorsGroup {
            GetScript = { return @{'Result' = ''} }
            SetScript = { Add-LocalGroupMember -Group "Administrators" -Member "PRKRLABS\WVDAdmins" -ErrorAction SilentlyContinue }
            TestScript = {
                $Members = Get-LocalGroupMember -Group "Administrators" | Foreach-Object {$_.Name}
                If ($Members -contains "PRKRLABS\WVDAdmins") { Return $true }
                Else { Return $false }
            }
        }
        # WVD Packages
        Script WVDSoftwarePackage {
            GetScript = { Return @{ 'Result' = '' } }
            TestScript = {
                If (Test-Path -Path ($env:TEMP + "\wvd_packages.zip")) {
                    $currentZip = Get-ChildItem -Path ($env:TEMP + "\wvd_packages.zip")
                    $remoteZip = Get-ChildItem -Path ($using:wvdArtifactLocation + "\wvd_packages.zip")
                    return ($currentZip.CreationTimeUtc -ge $remoteZip.CreationTimeUtc)
                }
                else { return $false }
            }
            SetScript = {
                Start-BitsTransfer -Source ($using:wvdArtifactLocation + "\wvd_packages.zip") -Destination ($env:TEMP + "\wvd_packages.zip")
                If (Test-Path -Path ($env:TEMP + "\wvd_packages.zip")) { Expand-Archive -Path ($env:TEMP + "\wvd_packages.zip") -DestinationPath ($using:vaConfigDataPath + "\DSC") -Force }
            }
        }
        # Powershell Modules
        Script PowerShellModules {
            GetScript = { Return @{ 'Result' = '' } }
            TestScript = { Return $false }
            SetScript = {
                Find-PackageProvider NuGet -Force | Install-PackageProvider -Force | Out-Null
                Install-PackageProvider PowerShellGet -Force | Out-Null

                # Check / Install Azure PowerShell Module
                Write-Verbose "Checking Az Module"
                $azModuleCheck = Get-InstalledModule Az -ErrorAction SilentlyContinue
                If ($azModuleCheck) {
                    $azModule = Find-Module Az
                    If ($azModule.Version -gt $azModuleCheck.Version) { $azModule | Install-Module -Force -AllowClobber }
                }
                Else { Find-Module Az | Install-Module -Force }

                # Check / Install Azure AD PowerShell Module
                Write-Verbose "Checking AzureAD Module"
                $azureADModuleCheck = Get-InstalledModule AzureAD -ErrorAction SilentlyContinue
                If ($azureADModuleCheck) {
                    $azureADModule = Find-Module AzureAD
                    If ($azureADModule.Version -gt $azureADModuleCheck.Version) { $azureADModule | Install-Module -Force -AllowClobber }
                }
                Else { Install-Module -Name AzureAD -Force }

                # Check / Install SharePoint Online PowerShell Module
                Write-Verbose "Checking Microsoft.Online.SharePoint.PowerShell Module"
                $spoModuleCheck = Get-InstalledModule "Microsoft.Online.SharePoint.PowerShell" -ErrorAction SilentlyContinue
                If ($spoModuleCheck) {
                    $spoModule = Find-Module "Microsoft.Online.SharePoint.PowerShell"
                    If ($spoModule.Version -gt $spoModuleCheck.Version) { $spoModule | Install-Module -Force -AllowClobber }
                }
                Else { Install-Module -Name "Microsoft.Online.SharePoint.PowerShell" -Force }

                # Check / Install Exchange Online PowerShell Module
                Write-Verbose "Checking ExchangeOnlineManagement Module"
                $exoModuleCheck = Get-InstalledModule ExchangeOnlineManagement -ErrorAction SilentlyContinue
                If ($exoModuleCheck) {
                    $exoModule = Find-Module ExchangeOnlineManagement
                    If ($exoModule.Version -gt $exoModuleCheck.Version) { $exoModule | Install-Module -Force -AllowClobber }
                }
                Else { Install-Module -Name ExchangeOnlineManagement -Force }

                # Check / Install SQL Server PowerShell Module
                Write-Verbose "Checking SqlServer Module"
                $sqlModuleCheck = Get-InstalledModule SqlServer -ErrorAction SilentlyContinue
                If ($sqlModuleCheck) {
                    $sqlModule = Find-Module SqlServer
                    If ($sqlModule.Version -gt $sqlModuleCheck.Version) { $sqlModule | Install-Module -Force -AllowClobber }
                }
                Else { Install-Module -Name SqlServer -Force }
            }
        }
        # Ensure directory for packages exists
        File CreatePackageDirectory {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = ("{0}\DSC\Packages" -f $wvdConfigDataPath)
        }
        #Create directory for MSI logs
        File CreateLogDirectory {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = ("{0}\Logs" -f $wvdConfigDataPath)
        }

        # WVD HostPool Registration
        If (Get-Command -Name isRdshServer) {
            $rdshIsServer = isRdshServer
            if ($rdshIsServer) {
                ("[{0}] {1} | rdshIsServer = TRUE" -f (Get-Date),$env:COMPUTERNAME) | Out-File "$wvdConfigDataPath\WVD\rdshIsServer_Results.log" -Append
                WindowsFeature RDS-RD-Server {
                    Ensure = "Present"
                    Name = "RDS-RD-Server"
                }

                PendingReboot AfterRDSFeatureInstall {
                    Name = "AfterRDSFeatureInstall"
                    DependsOn = "[WindowsFeature]RDS-RD-Server"
                }
    
                Script ExecuteRdAgentInstallServer {
                    DependsOn = "[WindowsFeature]RDS-RD-Server","[File]CreatePackageDirectory"
                    GetScript = { return @{'Result' = ''} }
                    SetScript = {
                        . ($using:wvdConfigDataPath + "\WVD\Functions.ps1")
                        try { & "$using:wvdConfigDataPath\WVD\Script-AddRdshServer.ps1" -HostPoolName $using:HostPoolName -RegistrationInfoToken $using:RegistrationInfoToken -EnableVerboseMsiLogging:($using:EnableVerboseMsiLogging) }
                        catch {
                            $ErrMsg = $PSItem | Format-List -Force | Out-String
                            Write-Log -Err $ErrMsg
                            throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallServer SetScript: $ErrMsg", $PSItem.Exception)
                        }
                    }
                    TestScript = {
                        . ($using:wvdConfigDataPath + "\WVD\Functions.ps1")
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
                ("[{0}] {1} | rdshIsServer = FALSE" -f (Get-Date),$env:COMPUTERNAME) | Out-File "$wvdConfigDataPath\WVD\rdshIsServer_Results.log" -Append
                Script ExecuteRdAgentInstallClient {
                    DependsOn = "[File]CreatePackageDirectory"
                    GetScript = { return @{'Result' = ''} }
                    SetScript = {
                        . ($using:wvdConfigDataPath + "\WVD\Functions.ps1")
                        try { & "$using:wvdConfigDataPath\WVD\Script-AddRdshServer.ps1" -HostPoolName $using:HostPoolName -RegistrationInfoToken $using:RegistrationInfoToken -EnableVerboseMsiLogging:($using:EnableVerboseMsiLogging) }
                        catch {
                            $ErrMsg = $PSItem | Format-List -Force | Out-String
                            Write-Log -Err $ErrMsg
                            throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallClient SetScript: $ErrMsg", $PSItem.Exception)
                        }
                    }
                    TestScript = {
                        . ($using:wvdConfigDataPath + "\WVD\Functions.ps1")
                        try { return (Test-path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent") }
                        catch {
                            $ErrMsg = $PSItem | Format-List -Force | Out-String
                            Write-Log -Err $ErrMsg
                            throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallClient TestScript: $ErrMsg", $PSItem.Exception)
                        }
                    }
                }
                #VDI/WVD Optimization Script
                Script VDI_Optimize {
                    TestScript = {
                        if ((Get-ScheduledTask MapsToastTask).State -eq "Disabled") { return $true }
                        else { return $false }
                    }
                    SetScript = { 
                        $version = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\").ReleaseId
                        If($version -eq "20H2" -or $version -eq "2009") { $version = "2004" }
                        powershell.exe -NonInteractive -File "$using:wvdConfigDataPath\DSC\Packages\optimizations\Win10_VirtualDesktop_Optimize.ps1" -WindowsVersion $version                    }
                    GetScript = {
                        @{ Result = ((Get-ScheduledTask MapsToastTask).State) }
                    }
                    DependsOn = "[File]CreatePackageDirectory"
                }
            }
        }
        Else { ("[{0}] {1} | Failed to find isRdshServer command - module didn't import" -f (Get-Date),$env:COMPUTERNAME) | Out-File "$vaConfigDataPath\WVD\rdsh_function_import.log" -Append }
        
        ## Network Tracing
        File CreateUtilitiesDirectory {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = "C:\Windows\Utilities\NetMon"
        }
        File CopyNetMonUtilities {
            Ensure = "Present"
            Type = "File"
            SourcePath = ("{0}\DSC\Packages\NetworkTracing\NetMonCleanUp.ps1" -f $wvdConfigDataPath)
            DestinationPath = "C:\Windows\Utilities\NetMonCleanUp.ps1"
            Force = $true
            DependsOn = "[File]CreateUtilitiesDirectory"
        }
        xPackage NetworkMonitor {
            Ensure = "Present"
            Name = "Microsoft Network Monitor 3.4"
            Path = ("{0}\DSC\Packages\NetworkTracing\NM34_x64.exe" -f $wvdConfigDataPath)
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
        xPackage VisualStudioCode {
            Ensure = "Present"
            Name = "Microsoft Visual Studio Code"
            Path = ("{0}\DSC\Packages\VSCode_v1.47.3\VSCodeSetup-x64-1.47.3.exe" -f $wvdConfigDataPath)
            ProductId = ''
            Arguments = ('/VERYSILENT /NORESTART /MERGETASKS=!runcode /LOG="{0}\Logs\VSCodeSetup-x64-1.47.3.log"' -f $wvdConfigDataPath)
            IgnoreReboot = $true
        }
        xPackage Git {
            Ensure = "Present"
            Name = "Git version 2.28.0"
            Path = ("{0}\DSC\Packages\Git_v2.28.0\Git-2.28.0-64-bit.exe" -f $wvdConfigDataPath)
            ProductId = ''
            Arguments = ('/VERYSILENT /NORESTART /LOG="{0}\Logs\Git-2.28.0-64-bit.log"' -f $wvdConfigDataPath)
            IgnoreReboot = $true
        }
        xPackage NotepadPlusPlus {
            Ensure = "Present"
            Name = "Notepad++ (64-bit x64)"
            Path = ("{0}\DSC\Packages\Notepad++\7.8.6\MSI\npp.7.8.6.Installer.x64.exe" -f $wvdConfigDataPath)
            ProductId = ''
            Arguments = '/S /noUpdater'
            IgnoreReboot = $true
        }
        xPackage PowerBIDesktop {
            Ensure = "Present"
            Name = "Microsoft PowerBI Desktop (x64)"
            Path = ("{0}\DSC\Packages\MicrosoftPowerBIDesktop\PBIDesktopSetup_x64.exe" -f $wvdConfigDataPath)
            ProductId = ""
            Arguments = "-quiet -norestart ACCEPT_EULA=1 DISABLE_UPDATE_NOTIFICATION=1"
            LogPath = "$wvdConfigDataPath\Logs\PBIDesktopSetup_x64.log"
            IgnoreReboot = $true
        }
        ## FSLogix
        xPackage FsLogix {
            Ensure = "Present"
            Name = "Microsoft FsLogix Apps"
            Path = ("{0}\DSC\Packages\FSLogix_Apps_2.9.7486.53382\x64\Release\FSLogixAppsSetup.exe" -f $wvdConfigDataPath)
            ProductId = ''
            Arguments = ("/norestart /quiet /log {0}\Logs\FSLogix_Apps_2.9.7486.53382.log" -f $wvdConfigDataPath)
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
        Script RebootPostInstall {
            TestScript = { return (Test-Path ("{0}\RebootPostInstall.txt" -f $wvdConfigDataPath)) }
            SetScript = {
                New-Item -Path $using:wvdConfigDataPath -Name "RebootPostInstall.txt" -ItemType "file"
                $global:DSCMachineStatus = 1
            }
            GetScript = {
                @{ Result = (Test-Path ("{0}\RebootPostInstall.txt" -f $wvdConfigDataPath)) }
            }
        }
    }
}