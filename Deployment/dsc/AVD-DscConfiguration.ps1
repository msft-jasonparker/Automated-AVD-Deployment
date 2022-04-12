Configuration AvdSessionHostConfig {
    Param (
        [System.String]$azCloud,
        [System.String]$avdHostPoolName,
        [System.String]$avdHostPoolToken,
        [System.String]$avdLogAnalyticsWorkspaceId,
        [System.String]$avdLogAnalyticsWorkspaceKey,
        [System.String]$avdConfigurationZip,
        [System.String]$avdEnvironment,
        [System.String]$avdWorkload,
        [System.String]$avdVirtualMachineType,
        [System.String]$avdBuildType,
        [System.String]$avdDeploymentGuid,
        [System.String]$avdfsLogixVhdLocation,
        [System.String]$avdBaselineZip,
        [System.String]$avdDesktopZip,
        [System.String]$avdServerZip,
        [System.String]$avdCanaryZip,
        [System.Boolean]$avdCanary,
        [System.String[]]$avdLocalAdminGroups
    )
    Set-ExecutionPolicy "RemoteSigned" -Scope Process -Confirm:$false
    Set-ExecutionPolicy "RemoteSigned" -Scope CurrentUser -Confirm:$false

    # DSC Modules Import
    Import-DSCResource -ModuleName "PSDesiredStateConfiguration"
    Import-DSCResource -ModuleName "xPSDesiredStateConfiguration" -ModuleVersion 9.1.0
    Import-DscResource -ModuleName "ComputerManagementDsc" -ModuleVersion 8.4.0

    $avdConfigDataPath = "C:\ProgramData\AzureVirtualDesktop"

    Node localhost {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }
        # [--------------------------| Baseline: Expand Drive Size |--------------------------------]
        Script BaselineExpandDrive {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = {
                If ((Get-Service -Name defragsvc).StartType -eq 'Disabled') {
                    Set-Service -Name defragsvc -StartupType Manual
                }
                Start-Service -Name defragsvc

                $pnum = (Get-Partition -DriveLetter C).PartitionNumber
                $free = (Get-Disk -Number 0).LargestFreeExtent
                $max = (Get-PartitionSupportedSize -DiskNumber 0 -PartitionNumber $pnum).SizeMax

                Stop-Service -Name defragsvc
                Set-Service -Name defragsvc -StartupType Disabled

                if ($free -gt 0 -and $free -le $max) { return $false }
                else { return $true }
            }
            SetScript  = {
                If ((Get-Service -Name defragsvc).StartType -eq 'Disabled') {
                    Set-Service -Name defragsvc -StartupType Manual
                }
                Start-Service -Name defragsvc

                $pnum = (Get-Partition -DriveLetter C).PartitionNumber
                $free = (Get-Disk -Number 0).LargestFreeExtent
                $max = (Get-PartitionSupportedSize -DiskNumber 0 -PartitionNumber $pnum).SizeMax

                if ($free -gt 0 -and $free -le $max) { 
                    Resize-Partition -DriveLetter C -Size (Get-PartitionSupportedSize -DiskNumber 0 -PartitionNumber $pnum).SizeMax 
                }
                
                Stop-Service -Name defragsvc
                Set-Service -Name defragsvc -StartupType Disabled
            }
        }
        Service DefragService {
            DependsOn   = "[Script]BaselineExpandDrive"
            Ensure      = "Present"
            StartupType = "Disabled"
            Name        = "defragsvc"
            State       = "Stopped"
            DisplayName = "Optimize drives"
        }
        # [--------------------------| Baseline: Multi-Home MMA when deployed in GOV |--------------------------------]
        If ($azCloud -eq "MAG") {
            Script MMA-AzureCommercial {
                GetScript   = { Return @{ 'Result' = '' } }
                TestScript  = { Test-Path ("HKLM:\SYSTEM\ControlSet001\Services\HealthService\Parameters\Service Connector Services\Log Analytics - {0}\" -f $using:avdLogAnalyticsWorkspaceId ) }
                SetScript   = {
                    $laWorkspaceId = $using:avdLogAnalyticsWorkspaceId
                    $laWorkspaceKey = $using:avdLogAnalyticsWorkspaceKey
                    $mmaAgent = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg'
                    $mmaAgent.AddCloudWorkspace($laWorkspaceId, $laWorkspaceKey)
                    $mmaAgent.ReloadConfiguration()
                }
            }
        }
        # [--------------------------| Baseline:  VA Config Data Path Directory Setup |--------------------------]
        File CreateLogDirectory {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = ("{0}\Logs" -f $avdConfigDataPath)
        }
        File CreateDSCDirectory {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = ("{0}\DSC" -f $avdConfigDataPath)
        }
        File CreateTempDirectory {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = ("{0}\Temp" -f $avdConfigDataPath)
        }
        File CreateAVDDirectory {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = ("{0}\AVD" -f $avdConfigDataPath)
        }
        File CreateUtilitiesDirectory {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = "C:\Windows\Utilities\NetMon"
        }
        File CreateSystemTempDirectory {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = ("C:\TEMP")
        }
        Script SystemTempACLUpdate {
            DependsOn   = "[File]CreateSystemTempDirectory"
            GetScript   = { Return @{ 'Result' = '' } }
            TestScript  = {
                $accessHashTable = @{
                    "CREATOR OWNER"             =   "Write"
                    "SYSTEM"                    =   "FullControl"
                    "BUILTIN\Users"             =   "Modify"
                    "BUILTIN\Administrators"    =   "FullControl"
                }

                $aclObject = Get-Acl -Path ("C:\TEMP") -ErrorAction SilentlyContinue
                # Clear existing permissions and block inheritance
                $aclObject.SetAccessRuleProtection($true, $false)

                # Set new ACL(s) on ACLObject looping through the access hash table
                Foreach ($Account in $accessHashTable.Keys) {
                    # Create the permission object per account in the hash table
                    $permissionObject = $Account, $accessHashTable[$Account], "ContainerInherit,ObjectInherit", "None", "Allow"
                    # Create ACL access rule and apply permission object
                    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($permissionObject)
                    # Apply the access rule to the ACL Object
                    $aclObject.SetAccessRule($accessRule)
                }

                # Validate ACL
                $initalAclCheck = Compare-Object -ReferenceObject $aclObject.GetSecurityDescriptorSddlForm("All") -DifferenceObject (Get-Acl -Path ("C:\TEMP") -ErrorAction SilentlyContinue).GetSecurityDescriptorSddlForm("All") -ErrorAction SilentlyContinue
                If ($initalAclCheck) { Return $false }
                Else { Return $true }
            }
            SetScript   = {
                $accessHashTable = @{
                    "CREATOR OWNER"             =   "Write"
                    "SYSTEM"                    =   "FullControl"
                    "BUILTIN\Users"             =   "Modify"
                    "BUILTIN\Administrators"    =   "FullControl"
                }

                $aclObject = Get-Acl -Path ("C:\TEMP") -ErrorAction SilentlyContinue
                # Clear existing permissions and block inheritance
                $aclObject.SetAccessRuleProtection($true, $false)

                # Set new ACL(s) on ACLObject looping through the access hash table
                Foreach ($Account in $accessHashTable.Keys) {
                    # Create the permission object per account in the hash table
                    $permissionObject = $Account, $accessHashTable[$Account], "ContainerInherit,ObjectInherit", "None", "Allow"
                    # Create ACL access rule and apply permission object
                    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($permissionObject)
                    # Apply the access rule to the ACL Object
                    $aclObject.SetAccessRule($accessRule)
                }

                # Validate ACL
                $initalAclCheck = Compare-Object -ReferenceObject $aclObject.GetSecurityDescriptorSddlForm("All") -DifferenceObject (Get-Acl -Path ("C:\TEMP") -ErrorAction SilentlyContinue).GetSecurityDescriptorSddlForm("All") -ErrorAction SilentlyContinue
                If ($initalAclCheck) { ("{0} `t [WARNING] `t ACL(s) on the folder 'C:\TEMP' do not match" -f (Get-Date -Format s)) | Out-File -FilePath ("{0}\Logs\SystemTempACLUpdate.log" -f $using:avdConfigDataPath) -Append  }
                Else {
                    ("{0} `t [INFO] `t No change need for ACL(s) on folder 'C:\TEMP'" -f (Get-Date -Format s)) | Out-File -FilePath ("{0}\Logs\SystemTempACLUpdate.log" -f $using:avdConfigDataPath) -Append 
                    Break
                }

                # Apply ACL to target
                $newAclObject = Set-Acl -Path ("C:\TEMP") -AclObject $aclObject -PassThru -ErrorAction SilentlyContinue

                If ($newAclObject) {
                    $aclValidation = Compare-Object -ReferenceObject $aclObject.GetSecurityDescriptorSddlForm("All") -DifferenceObject $newAclObject.GetSecurityDescriptorSddlForm("All") -ErrorAction SilentlyContinue
                    If ($aclValidation) { ("{0} `t [FAILED] `t ACL(s) on the folder 'C:\TEMP', were not applied correctly" -f (Get-Date -Format s)) | Out-File -FilePath ("{0}\Logs\SystemTempACLUpdate.log" -f $using:avdConfigDataPath) -Append }
                    Else { ("{0} `t [SUCCESS] `t Applied new ACL(s) on folder 'C:\TEMP'" -f (Get-Date -Format s)) | Out-File -FilePath ("{0}\Logs\SystemTempACLUpdate.log" -f $using:avdConfigDataPath) -Append  }
                }
                Else { ("{0} `t [ERROR] `t Unable to get newly applied ACL(s) from folder 'C:\TEMP'" -f (Get-Date -Format s)) | Out-File -FilePath ("{0}\Logs\SystemTempACLUpdate.log" -f $using:avdConfigDataPath) -Append }
            }
        }
        If ($avdLocalAdminGroups) {
            Script AvdLocalAdmins {
                GetScript  = { Return @{ 'Result' = '' } }
                TestScript = { Return $false }
                SetScript  = {
                    $LocalAdminMembers = Get-LocalGroupMember -Group "Administrators" | Foreach-Object {$_.Name}
                    Foreach ($Group in $using:avdLocalAdminGroups) {
                        If ($LocalAdminMembers -notcontains $Group) { Add-LocalGroupMember -Group Administrators -Member $Group }
                    }
                }
            }
        }
        # [--------------------------| Baseline:  AVD Agent Download |--------------------------]
        Script AVDConfigurationDownload {
            DependsOn  = '[File]CreateTempDirectory'
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = { Test-Path -Path ("{0}\AVD\Script-SetupSessionHost.ps1" -f $using:avdConfigDataPath) }
            SetScript  = {
                try {
                    (New-Object System.Net.WebClient).DownloadFile($using:avdConfigurationZip, ("{0}\Temp\avd_configuration.zip" -f $using:avdConfigDataPath))
                    Expand-Archive -Path ("{0}\Temp\avd_configuration.zip" -f $using:avdConfigDataPath) -DestinationPath ("{0}\AVD" -f $using:avdConfigDataPath) -Force
                }
                catch { Throw [System.Exception]::new(("Failed to download file: {0}" -f $using:avdConfigurationZip), "FileNotFound") }
            }
        }
        # [--------------------------| Baseline:  AVD Package Download |--------------------------]
        Script BaselinePackageDownload {
            DependsOn  = '[File]CreateTempDirectory'
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = { Test-Path -Path ("{0}\Logs\baseline_avd_packages_extracted.log" -f $using:avdConfigDataPath) }
            SetScript  = {
                try {
                    If (Test-Path -Path ("{0}\Temp\baseline_avd_packages.zip" -f $using:avdConfigDataPath)) {
                        Expand-Archive -Path ("{0}\Temp\baseline_avd_packages.zip" -f $using:avdConfigDataPath) -DestinationPath ("{0}\DSC" -f $using:avdConfigDataPath) -Force
                        New-Item -Path ("{0}\Logs\baseline_avd_packages_extracted.log" -f $using:avdConfigDataPath) -ItemType File -Value (Get-Date -Format o) -Force
                    }
                    Else {
                        (New-Object System.Net.WebClient).DownloadFile($using:avdBaselineZip, ("{0}\Temp\baseline_avd_packages.zip" -f $using:avdConfigDataPath))
                        Expand-Archive -Path ("{0}\Temp\baseline_avd_packages.zip" -f $using:avdConfigDataPath) -DestinationPath ("{0}\DSC" -f $using:avdConfigDataPath) -Force
                        New-Item -Path ("{0}\Logs\baseline_avd_packages_extracted.log" -f $using:avdConfigDataPath) -ItemType File -Value (Get-Date -Format o) -Force
                    }                    
                }
                catch { Throw [System.Exception]::new(("Failed to download and extract file: {0}" -f $using:avdBaselineZip), "FileNotFound") }
            }
        }
        # Build Specific Install for AVD Agent
        # [--------------------------| AVD Agent Install |--------------------------]
        If ($avdVirtualMachineType -eq "SERVER") {
            WindowsFeature RDS-RD-Server {
                Ensure = "Present"
                Name   = "RDS-RD-Server"
            }
            PendingReboot AfterRDSFeatureInstall {
                Name      = "AfterRDSFeatureInstall"
                DependsOn = "[WindowsFeature]RDS-RD-Server"
            }
            Script AVDAgentInstall-SERVER {
                DependsOn  = "[Script]AVDConfigurationDownload", "[PendingReboot]AfterRDSFeatureInstall"
                GetScript  = { Return @{ 'Result' = '' } }
                TestScript = { Test-path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent" }
                SetScript  = {
                    try { & ("{0}\AVD\Script-SetupSessionHost.ps1" -f $using:avdConfigDataPath) -HostPoolName $using:avdHostPoolName -RegistrationInfoToken $using:avdHostPoolToken -SessionHostConfigurationLastUpdateTime ([datetime]::Now).ToString() }
                    catch {
                        $ErrMsg = $PSItem | Format-List -Force | Out-String
                        Write-Log -Err $ErrMsg
                        throw [System.Exception]::new("Some error occurred in DSC AVDAgentInstall SetScript: $ErrMsg", $PSItem.Exception)
                    }
                }
            }
        }
        Else {
            Script AVDAgentInstall {
                DependsOn  = "[Script]AVDConfigurationDownload"
                GetScript  = { Return @{ 'Result' = '' } }
                TestScript = { Test-path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent" }
                SetScript  = {
                    try { & ("{0}\AVD\Script-SetupSessionHost.ps1" -f $using:avdConfigDataPath) -HostPoolName $using:avdHostPoolName -RegistrationInfoToken $using:avdHostPoolToken -SessionHostConfigurationLastUpdateTime ([datetime]::Now).ToString() }
                    catch {
                        $ErrMsg = $PSItem | Format-List -Force | Out-String
                        Write-Log -Err $ErrMsg
                        throw [System.Exception]::new("Some error occurred in DSC AVDAgentInstall SetScript: $ErrMsg", $PSItem.Exception)
                    }
                }
            }
        }
        # [--------------------------| Baseline: PowerShell Modules |--------------------------]
        Script PowerShellNugetProvider {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = {
                $remoteNuget = Find-PackageProvider Nuget
                $localNuget = Get-PackageProvider Nuget
                Return ($localNuget.Version.ToString() -ge $remoteNuget.Version)
            }
            SetScript  = { Find-PackageProvider Nuget | Install-PackageProvider -Scope AllUsers -Force }
        }
        Script PowerShellGetProvider {
            GetScript  = { Return @{ 'Result' = '' } }
            TestScript = {
                $remotePSGet = Find-PackageProvider PowerShellGet
                $localPSGet = Get-PackageProvider PowerShellGet
                Return ($localPSGet.Version.ToString() -ge $remotePSGet.Version)
            }
            SetScript  = { Find-PackageProvider PowerShellGet | Install-PackageProvider -Scope AllUsers -Force }
        }
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
            SetScript  = { Find-Module "Microsoft.Online.SharePoint.PowerShell" | Install-Module -AllowClobber -Force }
        }
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
            SetScript  = { Find-Module ExchangeOnlineManagement | Install-Module -AllowClobber -Force }
        }
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
            SetScript  = { Find-Module SqlServer | Install-Module -AllowClobber -Force }
        }
        Registry FsLogixProfileEnabled {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "Enabled"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry FsLogixConcurrentUserSessions {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "ConcurrentUserSessions"
            ValueData = "0"
            ValueType = "DWORD"
        }
        Registry FsLogixDeleteLocalProfileWhenVHDShouldApply {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "DeleteLocalProfileWhenVHDShouldApply"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry FsLogixPreventLoginWithFailure {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "PreventLoginWithFailure"
            ValueData = "0"
            ValueType = "DWORD"
        }
        Registry FsLogixPreventLoginWithTempProfile {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "PreventLoginWithTempProfile"
            ValueData = "0"
            ValueType = "DWORD"
        }
        Registry FsLogixLockedRetryCount {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "LockedRetryCount"
            ValueData = "3"
            ValueType = "DWORD"
        }
        Registry FsLogixVolumeType {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VolumeType"
            ValueData = "vhdx"
            ValueType = "string"
        }
        Registry FsLogixVHDNamePattern {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VHDNamePattern"
            ValueData = "%username%_Profile"
            ValueType = "string"
        }
        Registry FsLogixVHDNameMatch {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "VHDNameMatch"
            ValueData = "%username%_Profile"
            ValueType = "string"
        }
        Registry FsLogixFlipFlopProfileDirectoryName {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
            ValueName = "FlipFlopProfileDirectoryName"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry FsLogixCleanupInvalidSessions {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\FSLogix\Apps"
            ValueName = "CleanupInvalidSessions"
            ValueData = "1"
            ValueType = "DWORD"
        }
        Registry OneDriveRailRunOnce {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RailRunOnce'
            ValueName = 'OneDrive'
            ValueData = '"C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe" /background'
            ValueType = 'ExpandString'
        }
        Registry MicrosoftOneDriveRunOneDrive {
            Ensure    = "Present"
            Key       = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
            ValueName = "OneDrive"
            ValueData = "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe /background"
            ValueType = "String"
        }
        Registry MicrosoftOneDriveSilentAccountConfig {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
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
        # [--------------------------| Baseline:  Microsoft Network Monitor |--------------------------]
        File CopyNetMonUtilities {
            Ensure          = "Present"
            Type            = "File"
            SourcePath      = ("{0}\DSC\Packages\Microsoft\NetMon\NetMonCleanUp.ps1" -f $avdConfigDataPath)
            DestinationPath = "C:\Windows\Utilities\NetMonCleanUp.ps1"
            Force           = $true
            DependsOn       = "[File]CreateUtilitiesDirectory", "[Script]BaselinePackageDownload"
        }
        xPackage NetworkMonitor {
            Ensure       = "Present"
            Name         = "Microsoft Network Monitor 3.4"
            Path         = ("{0}\DSC\Packages\Microsoft\NetMon\3.4\MSI\NM34_x64.exe" -f $avdConfigDataPath)
            ProductId    = ''
            Arguments    = "/Q"
            IgnoreReboot = $true
            DependsOn    = "[Script]BaselinePackageDownload", "[File]CopyNetMonUtilities"
        }
        ScheduledTask EnableNetMonTracing {
            Ensure            = "Present"
            Enable            = $true
            TaskName          = "NetMonCapture"
            TaskPath          = "\Microsoft\Windows\NetTrace"
            ActionExecutable  = "C:\Program Files\Microsoft Network Monitor 3\nmcap.exe"
            ActionArguments   = "/Network * /Capture /MaxFrameLength 256 /File C:\Windows\Utilities\NetMon\%computername%.chn:25MB"
            Description       = "Starts NetMon Tracing at user logon"
            ScheduleType      = "AtLogon"
            BuiltInAccount    = "SYSTEM"
            Priority          = 7
            RunLevel          = "Highest"
            MultipleInstances = "IgnoreNew"
            RunOnlyIfIdle     = $false
            DependsOn         = "[xPackage]NetworkMonitor"
        }
        ScheduledTask NetMonTracingCleanUp {
            Ensure                    = "Present"
            Enable                    = $true
            TaskName                  = "NetMonCleanUp"
            TaskPath                  = "\Microsoft\Windows\NetTrace"
            ActionExecutable          = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            ActionArguments           = "-NoProfile -NonInteractive -File NetMonCleanUp.ps1"
            ActionWorkingPath         = "C:\Windows\Utilities"
            Description               = "Runs PowerShell script to clean up old NetMon capture files"
            StartTime                 = '2020-01-01T10:00:00'
            SynchronizeAcrossTimeZone = $true
            ScheduleType              = "Daily"
            DaysInterval              = 1
            ExecutionTimeLimit        = "01:00:00"
            BuiltInAccount            = "SYSTEM"
            Priority                  = 7
            RunLevel                  = "Highest"
            MultipleInstances         = "IgnoreNew"
            RunOnlyIfIdle             = $false
            DependsOn                 = "[ScheduledTask]EnableNetMonTracing"
        }
        # Build Specific Configurations
        Switch ($avdWorkload) {
            "W11" {
                Switch ($avdBuildType) {
                    "MAIN" {
                        # [--------------------------| Desktop-MAIN:  FsLogix Registry |--------------------------]
                        Registry FsLogixProfileVhdLocations {
                            Ensure    = "Present"
                            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
                            ValueName = "VHDLocations"
                            ValueData = ("{0}" -f $avdfsLogixVhdLocation)
                            ValueType = "MultiString"
                        }
                        Registry FsLogixProfileSize {
                            Ensure    = "Present"
                            Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
                            ValueName = "SizeInMBs"
                            ValueData = "30000"
                            ValueType = "DWORD"
                        }
                    }
                }
                # [--------------------------| Desktop:  Package Download |--------------------------]
                Script DesktopPackageDownload {
                    DependsOn  = "[Script]BaselinePackageDownload", '[File]CreateTempDirectory'
                    GetScript  = { Return @{ 'Result' = '' } }
                    TestScript = { Test-Path -Path ("{0}\Logs\Desktop_avd_packages_extracted.log" -f $using:avdConfigDataPath) }
                    SetScript  = {
                        try {
                            If ( Test-Path -Path ("{0}\Temp\Desktop_avd_packages.zip" -f $using:avdConfigDataPath) ) {
                                Expand-Archive -Path ("{0}\Temp\Desktop_avd_packages.zip" -f $using:avdConfigDataPath) -DestinationPath ("{0}\DSC" -f $using:avdConfigDataPath) -Force
                                New-Item -Path ("{0}\Logs\Desktop_avd_packages_extracted.log" -f $using:avdConfigDataPath) -ItemType File -Value (Get-Date -Format o) -Force
                            }
                            Else {
                                (New-Object System.Net.WebClient).DownloadFile($using:avdDesktopZip, ("{0}\Temp\Desktop_avd_packages.zip" -f $using:avdConfigDataPath) )
                                Expand-Archive -Path ("{0}\Temp\Desktop_avd_packages.zip" -f $using:avdConfigDataPath) -DestinationPath ("{0}\DSC" -f $using:avdConfigDataPath) -Force
                                New-Item -Path ("{0}\Logs\Desktop_avd_packages_extracted.log" -f $using:avdConfigDataPath) -ItemType File -Value (Get-Date -Format o) -Force
                            }
                        }
                        catch { Throw [System.Exception]::new(("Failed to download and extract file: {0}" -f $using:avdDesktopZip), "FileNotFound") }
                    }
                }
                # [--------------------------| Desktop:  Microsoft Office 365 |--------------------------]
                Registry OfficeDisableADAL {
                    Ensure    = "Present"
                    Key       = "HKEY_USERS\.DEFAULT\Software\Microsoft\Office\16.0\Common\Identity"
                    ValueName = "DisableADALatopWAMOverride"
                    ValueData = "1"
                    ValueType = "DWORD"
                    DependsOn = "[Script]DesktopPackageDownload"
                }
                # [--------------------------| Desktop:  Microsoft Teams |--------------------------]
                Registry EnableTeamsWVD {
                    Ensure    = "Present"
                    Key       = "HKLM:\SOFTWARE\\Microsoft\Teams"
                    ValueName = "IsWVDEnvironment"
                    ValueData = "1"
                    ValueType = "DWORD"
                }
                xPackage MSTeams {
                    Ensure       = "Present"
                    Name         = "Teams Machine-Wide Installer"
                    Path         = ("{0}\DSC\Packages\Microsoft\Teams Machine-Wide Installer\MSI\Teams_windows_x64.msi" -f $avdConfigDataPath)
                    ProductId    = "731F6BAA-A986-45A4-8936-7C3AAAAA760B"
                    Arguments    = "ALLUSER=1 ALLUSERS=1"
                    LogPath      = "$avdConfigDataPath\Logs\MicrosoftTeamsx64.log"
                    IgnoreReboot = $true
                    DependsOn    = "[Script]DesktopPackageDownload", "[Registry]EnableTeamsWVD"
                }
                xPackage MSTeamsRdpWebRtcRedirectorService {
                    Ensure       = "Present"
                    Name         = "Remote Desktop WebRTC Redirector Service"
                    Path         = ("{0}\DSC\Packages\Microsoft\Teams Machine-Wide Installer\MsRdcWebRTCSvc_HostSetup_1.4.2111.18001_x64.msi" -f $avdConfigDataPath)
                    ProductId    = "729B4FCB-E748-4ED0-978D-72512B332017"
                    Arguments    = "ALLUSERS=1 REBOOT=R"
                    LogPath      = ("{0}\Logs\MsRdcWebRTCSvc_HostSetup.log" -f $avdConfigDataPath)
                    IgnoreReboot = $true
                    DependsOn    = "[xPackage]MSTeams"
                }
                # [--------------------------| Desktop:  Microsoft Remote Desktop 64-bit |--------------------------]
                xPackage RemoteDesktop {
                    Ensure       = 'Present'
                    Name         = 'Remote Desktop'
                    Path         = ('{0}\DSC\Packages\Microsoft\Remote Desktop\RemoteDesktop_1.2.2860.0_x64.msi' -f $avdConfigDataPath)
                    ProductId    = '742205F4-5577-485F-89C9-DC0382262111'
                    Arguments    = 'ALLUSERS=1 REBOOT=R /qn'
                    LogPath      = ('{0}\Logs\RemoteDesktop_x64_Install.log' -f $avdConfigDataPath)
                    IgnoreReboot = $true
                    DependsOn    = "[Script]DesktopPackageDownload"
                }
                # [--------------------------| Desktop:  VDI Optimize |--------------------------]
                Script VDI_Optimize {
                    DependsOn  = "[Script]DesktopPackageDownload"
                    GetScript  = { Return @{ 'Result' = '' } }
                    TestScript = { ((Get-ScheduledTask MapsToastTask).State -eq "Disabled") }
                    SetScript  = {
                        Start-Process PowerShell.exe -WorkingDirectory ("{0}\DSC\Packages\VDI-Optimize" -f $using:avdConfigDataPath) -ArgumentList ".\Win10_VirtualDesktop_Optimize.ps1 -Optimizations AppxPackages,Autologgers,DefaultUserSettings,NetworkOptimizations,ScheduledTasks,Services -AcceptEULA -Verbose" -Verb RunAs -WindowStyle Hidden -Wait
                    }
                }
            }
            "ADM" {
                # [--------------------------| ADM:  Package Download |--------------------------]
                Script ADMPackageDownload {
                    DependsOn  = "[Script]BaselinePackageDownload", '[File]CreateTempDirectory'
                    GetScript  = { Return @{ 'Result' = '' } }
                    TestScript = { Test-Path -Path ("{0}\Logs\adm_avd_packages_extracted.log" -f $using:avdConfigDataPath) }
                    SetScript  = {
                        try {
                            If ( Test-Path -Path ("{0}\Temp\adm_avd_packages.zip" -f $using:avdConfigDataPath) ) {
                                Expand-Archive -Path ("{0}\Temp\adm_avd_packages.zip" -f $using:avdConfigDataPath) -DestinationPath ("{0}\DSC" -f $using:avdConfigDataPath) -Force
                                New-Item -Path ("{0}\Logs\adm_avd_packages_extracted.log" -f $using:avdConfigDataPath) -ItemType File -Value (Get-Date -Format o) -Force
                            }
                            Else {
                                (New-Object System.Net.WebClient).DownloadFile($using:avdADMZip, ("{0}\Temp\adm_avd_packages.zip" -f $using:avdConfigDataPath) )
                                Expand-Archive -Path ("{0}\Temp\adm_avd_packages.zip" -f $using:avdConfigDataPath) -DestinationPath ("{0}\DSC" -f $using:avdConfigDataPath) -Force
                                New-Item -Path ("{0}\Logs\adm_avd_packages_extracted.log" -f $using:avdConfigDataPath) -ItemType File -Value (Get-Date -Format o) -Force
                            }
                        }
                        catch { Throw [System.Exception]::new(("Failed to download and extract file: {0}" -f $using:avdADMZip), "FileNotFound") }
                    }
                }
                # [--------------------------| ADM:  FsLogix Registry |--------------------------]
                Registry FsLogixProfileVhdLocations {
                    Ensure    = "Present"
                    Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
                    ValueName = "VHDLocations"
                    ValueData = ("{0}\_ADMIN" -f $avdfsLogixVhdLocation)
                    ValueType = "MultiString"
                }
                Registry FsLogixProfileSize {
                    Ensure    = "Present"
                    Key       = "HKLM:\SOFTWARE\FSLogix\Profiles"
                    ValueName = "SizeInMBs"
                    ValueData = "30000"
                    ValueType = "DWORD"
                }
                # [--------------------------| ADM:  Remote Admin Tools |--------------------------]
                WindowsFeatureSet RemoteAdministrationTools {
                    Ensure               = 'Present'
                    Name                 = 'RSAT'
                    IncludeAllSubFeature = $true
                }
                WindowsFeature GroupPolicyManagement {
                    Ensure = 'Present'
                    Name   = 'GPMC'
                }
                WindowsFeature FSFileServer {
                    Ensure = 'Present'
                    Name   = 'FS-FileServer'
                }
                WindowsFeature FSDFSNamespace {
                    Ensure = 'Present'
                    Name   = 'FS-DFS-Namespace'
                }
                WindowsFeature FSDFSReplication {
                    Ensure = 'Present'
                    Name   = 'FS-DFS-Replication'
                }
                File AdminToolsDesktopFolder {
                    Ensure          = "Present"
                    Type            = "Directory"
                    DestinationPath = "C:\Users\Public\Desktop\Admin Tools"
                }
                Script CopyAdminToolShortcuts {
                    DependsOn  = "[File]AdminToolsDesktopFolder"
                    GetScript  = { @{ Result = '' } }
                    TestScript = {
                        If (Test-Path -Path "C:\Users\Public\Desktop\Admin Tools") { Return $false }
                        Else { Return $true }
                    }
                    SetScript  = { Copy-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\*.lnk" -Destination "C:\Users\Public\Desktop\Admin Tools" -Force }
                }
            }
            Default {}
        }
        # Canary Application / Configuration Testing
        # Any applications or configurations placed in the section below are considered experimental and may break AVD deployments
        If ($avdCanary) {
            # [--------------------------| Canary:  Package Download |--------------------------]
            Script CanaryPackageDownload {
                DependsOn  = "[Script]BaselinePackageDownload", '[File]CreateTempDirectory'
                GetScript  = { Return @{ 'Result' = '' } }
                TestScript = { Test-Path -Path ("{0}\Logs\canary_avd_packages_extracted.log" -f $using:avdConfigDataPath) }
                SetScript  = {
                    try {
                        If ( Test-Path -Path ("{0}\Temp\canary_avd_packages.zip" -f $using:avdConfigDataPath) ) {
                            Expand-Archive -Path ("{0}\Temp\canary_avd_packages.zip" -f $using:avdConfigDataPath) -DestinationPath ("{0}\DSC" -f $using:avdConfigDataPath) -Force
                            New-Item -Path ("{0}\Logs\canary_avd_packages_extracted.log" -f $using:avdConfigDataPath) -ItemType File -Value (Get-Date -Format o) -Force
                        }
                        Else {
                            (New-Object System.Net.WebClient).DownloadFile($using:avdCanaryZip, ("{0}\Temp\canary_avd_packages.zip" -f $using:avdConfigDataPath) )
                            Expand-Archive -Path ("{0}\Temp\canary_avd_packages.zip" -f $using:avdConfigDataPath) -DestinationPath ("{0}\DSC" -f $using:avdConfigDataPath) -Force
                            New-Item -Path ("{0}\Logs\canary_avd_packages_extracted.log" -f $using:avdConfigDataPath) -ItemType File -Value (Get-Date -Format o) -Force
                        }
                    }
                    catch { Throw [System.Exception]::new(("Failed to download and extract file: {0}" -f $using:avdCanaryZip), "FileNotFound") }
                }
            }
        }
        Script RebootPostInstall {
            GetScript  = { @{ Result = '' } }
            TestScript = { Test-Path -Path ("{0}\Logs\RebootPostInstall.txt" -f $using:avdConfigDataPath) }
            SetScript  = {
                New-Item -Path ("{0}\Logs" -f $using:avdConfigDataPath) -Name "RebootPostInstall.txt" -ItemType File
                $global:DSCMachineStatus = 1
            }
        }

    }
}