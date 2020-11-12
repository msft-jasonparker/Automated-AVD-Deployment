Configuration WvdSessionHostConfig
{
    Param (
        [string]$HostPoolName,
        [string]$RegistrationInfoToken,
        [string]$wvdDscConfigZipUrl,
        [string]$wvdArtifactLocation,
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
        ## Domain Join Sleep
        Script DomainJoinSleep {
            GetScript = { Return @{ 'Result' = '' } }
            TestScript = {
                If (Test-Path ("{0}\DomainJoinSleep.txt" -f $using:wvdConfigDataPath)) { Return $true }
                Else { Return $false }
            }
            SetScript = {
                New-Item -Path $using:wvdConfigDataPath -Name "DomainJoinSleep.txt" -ItemType "file"
                Start-Sleep -Seconds 60
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
            DependsOn = "[Script]DomainJoinSleep"
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
                $stopWatch = [system.diagnostics.stopwatch]::startnew()
                Start-BitsTransfer -Source ($using:wvdArtifactLocation + "\wvd_packages.zip") -Destination ($env:TEMP + "\wvd_packages.zip")
                If (Test-Path -Path ($env:TEMP + "\wvd_packages.zip")) { Expand-Archive -Path ($env:TEMP + "\wvd_packages.zip") -DestinationPath ($using:wvdConfigDataPath + "\DSC") -Force }
                $stopwatch.stop()
                $stopwatch.elapsed | out-file -path ("{0}\Logs\wvd_package.log" -f $using:wvdConfigDataPath)
            }
            DependsOn = "[Script]LocalAdministratorsGroup"
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
                    DependsOn = "[WindowsFeature]RDS-RD-Server","[Script]WVDSoftwarePackage"
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
                        If (Test-Path -Path ($using:wvdConfigDataPath + "\WVD\Functions.ps1")) {
                            . ($using:wvdConfigDataPath + "\WVD\Functions.ps1")
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
            }
            else {
                ("[{0}] {1} | rdshIsServer = FALSE" -f (Get-Date),$env:COMPUTERNAME) | Out-File "$wvdConfigDataPath\WVD\rdshIsServer_Results.log" -Append
                Script ExecuteRdAgentInstallClient {
                    DependsOn = "[Script]WVDSoftwarePackage"
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
                        If (Test-Path -Path ($using:wvdConfigDataPath + "\WVD\Functions.ps1")) {
                            . ($using:wvdConfigDataPath + "\WVD\Functions.ps1")
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
                #VDI/WVD Optimization Script
                Script VDI_Optimize {
                    TestScript = {
                        if ((Get-ScheduledTask MapsToastTask).State -eq "Disabled") { return $true }
                        else { return $false }
                    }
                    SetScript = {
                        try { & "$using:wvdConfigDataPath\DSC\Packages\VDIOptimize\Win10_VirtualDesktop_Optimize.ps1" -WindowsMediaPlayer -AppxPackages -ScheduledTasks -DefaultUserSettings -Autologgers -Services -NetworkOptimizations -LGPO -DiskCleanup -Verbose }
                        catch {
                            $ErrMsg = $PSItem | Format-List -Force | Out-String
                            throw [System.Exception]::new(("Error running VDI Script Resource: {0}" -f $ErrMsg),$PSItem.Exception)
                        }
                    }
                    GetScript = {
                        @{ Result = ((Get-ScheduledTask MapsToastTask).State) }
                    }
                    DependsOn = "[Script]WVDSoftwarePackage"
                }
            }
        }
        Else { ("[{0}] {1} | Failed to find isRdshServer command - module didn't import" -f (Get-Date),$env:COMPUTERNAME) | Out-File "$wvdConfigDataPath\WVD\rdsh_function_import.log" -Append }
        
        xPackage VisualStudioCode {
            Ensure = "Present"
            Name = "Microsoft Visual Studio Code"
            Path = ("{0}\DSC\Packages\VSCode\VSCodeSetup-x64-1.51.0.exe" -f $wvdConfigDataPath)
            ProductId = ''
            Arguments = ('/VERYSILENT /NORESTART /MERGETASKS=!runcode /LOG="{0}\Logs\VSCodeSetup-x64-1.51.0.log"' -f $wvdConfigDataPath)
            IgnoreReboot = $true
            DependsOn = "[Script]WVDSoftwarePackage"
        }
        xPackage Git {
            Ensure = "Present"
            Name = "Git version 2.29.0"
            Path = ("{0}\DSC\Packages\Git\Git-2.29.2.2-64-bit.exe" -f $wvdConfigDataPath)
            ProductId = ''
            Arguments = ('/VERYSILENT /NORESTART /LOG="{0}\Logs\Git-2.29.2.2-64-bit.log"' -f $wvdConfigDataPath)
            IgnoreReboot = $true
            DependsOn = "[Script]WVDSoftwarePackage"
        }
        xPackage NotepadPlusPlus {
            Ensure = "Present"
            Name = "Notepad++ (64-bit x64)"
            Path = ("{0}\DSC\Packages\Notepad++\npp.7.9.1.Installer.x64.exe" -f $wvdConfigDataPath)
            ProductId = ''
            Arguments = '/S /noUpdater'
            LogPath = "$wvdConfigDataPath\Logs\npp.7.9.1.Installer.x64.log"
            IgnoreReboot = $true
            DependsOn = "[Script]WVDSoftwarePackage"
        }
        xPackage PowerBIDesktop {
            Ensure = "Present"
            Name = "Microsoft PowerBI Desktop (x64)"
            Path = ("{0}\DSC\Packages\PowerBIDesktop\PBIDesktopSetup_x64.exe" -f $wvdConfigDataPath)
            ProductId = ""
            Arguments = "-quiet -norestart ACCEPT_EULA=1 DISABLE_UPDATE_NOTIFICATION=1"
            LogPath = "$wvdConfigDataPath\Logs\PBIDesktopSetup_x64.log"
            IgnoreReboot = $true
            DependsOn = "[Script]WVDSoftwarePackage"
        }
        ## FSLogix
        xPackage FsLogix {
            Ensure = "Present"
            Name = "Microsoft FsLogix Apps"
            Path = ("{0}\DSC\Packages\FSLogix\FSLogixAppsSetup.exe" -f $wvdConfigDataPath)
            ProductId = ''
            Arguments = ("/norestart /quiet /log {0}\Logs\FSLogixAppsSetup.log" -f $wvdConfigDataPath)
            IgnoreReboot = $true
            DependsOn = "[Script]WVDSoftwarePackage"
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
            GetScript = { return @{'Result' = ''} }
            TestScript = {
                If (Test-Path ("{0}\RebootPostInstall.txt" -f $using:wvdConfigDataPath)) { Return $true }
                Else { Return $false }
            }
            SetScript = {
                New-Item -Path $using:wvdConfigDataPath -Name "RebootPostInstall.txt" -ItemType "file"
                $global:DSCMachineStatus = 1
            }
        }
    }
}