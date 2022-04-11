Function Update-FSLogixProfilePermissions {
    <#
        .SYNOPSIS
            Updates the NTFS permissions on existing folders for FSLogix Profile Containers.
        .DESCRIPTION
            This cmdlet is used to fix or update the NTFS permissions for the folders FSLogix uses to storage profile containers.
    #>
    [CmdletBinding(DefaultParameterSetName="Default")]
    Param (
        [Parameter(Mandatory=$true,ParameterSetName="Default",Position=0)]
        [System.String]$Path,

        [Parameter(Mandatory=$true,ParameterSetName="Default",Position=1)]
        [System.String]$NetBIOSDomainName,
        
        [Parameter(Mandatory=$true,ParameterSetName="NetworkShare",Position=0)]
        [System.String]$ComputerName,

        [Parameter(Mandatory=$true,ParameterSetName="NetworkShare",Position=1)]
        [System.String]$ShareName,

        [Parameter(Mandatory=$false)]
        [Switch]$Recurse
    )

    BEGIN {
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        # Check to see if the Path parameter was provided
        If ($Path) {
            Write-Verbose ("Checking the provided path: '{0}'" -f $Path)
            # Test the path
            If (Test-Path -Path $Path) {
                Write-Verbose ("Collecting FSLogix Profile Directories")
                # Collect folders matching '_S-1'
                $profileFolders = Get-ChildItem -Path $Path -Directory -Recurse:$Recurse | Where-Object { $_.Name.Contains("_S-1") }
                Write-Verbose ("Found {0} Folders to Process from: {1}" -f $profileFolders.Count, $Path)
            }
            Else {
                Write-Warning ("Verify that the '{0}' path is valid" -f $Path)
                Break
            }
        }
        Else {
            $volumeSharePath = ("\\{0}\{1}" -f $ComputerName, $ShareName)
            Write-Verbose ("Testing the path: '{0}'" -f $volumeSharePath)
            # Test the path
            If (Test-Path -Path $volumeSharePath) {
                Write-Verbose ("Collecting FSLogix Profile Directories")
                # Collect folders matching '_S-1'
                $profileFolders = Get-ChildItem $volumeSharePath -Directory -Recurse:$Recurse | Where-Object { $_.Name.Contains("_S-1") }
                If ($profileFolders.Count -gt 0) { Write-Verbose ("Found {0} Folders to Process from: {1}" -f $profileFolders.Count, $volumeSharePath) }
                Else {
                    Write-Warning ("No FSLogix Profile Directories found matching '_S-1'")
                    Break
                }
            }
            Else {
                Write-Warning ("Verify that the '{0}' path is valid" -f $volumeSharePath)
                Break
            }
        }
    }
    PROCESS {
        $i = 1
        foreach ($Item in $profileFolders) {
            Write-Progress -Activity "Processing Folders" -Status ("Working on {0} of {1}" -f $i, $profileFolders.Count) -CurrentOperation $Item.FullName -PercentComplete (($i / $profileFolders.Count) * 100)
            # Parse folder name for username
            $userName = $item.Name.Split("_")[0]

            $userAccount = $null
            # query AD to check if user exsists
            $userAccount = _GetADAttributes -Property "samAccountName" -Value $userName

            Write-Debug "check user account"
            # if the user prinicpal is active 
            If ($null -ne $userAccount) {
                # Create domain\username variable
                If ($NetBIOSDomainName) { $User = ("{0}\{1}" -f $NetBIOSDomainName, $userAccount.samAccountName) }
                Else {
                    If ([System.String]::IsNullOrEmpty($userAccount.extensionattribute8)) { $User = ("{0}\{1}" -f $ShareName, $userAccount.samAccountName) }
                    Else { $User = ("{0}\{1}" -f $userAccount.extensionattribute8, $userAccount.samAccountName) }
                }

                # ACL Permission Hashtable
                $accessHashTable = @{
                    $User                           = "FullControl"
                    "SYSTEM"                        = "FullControl"
                    "VA\VAOITWindowsVirtualDesktop" = "FullControl"
                }

                # Get ACL(s) on folder
                $aclObject = Get-Acl -Path $Item.FullName -ErrorAction SilentlyContinue

                Write-Debug "check acl object"
                # Check for ACL Object
                If ($aclObject) {
                    # Clear existing permissions and block inheritance
                    $aclObject.SetAccessRuleProtection($true, $false)

                    # Set new ACL(s) on ACLObject looping through the access hash table
                    foreach ($Account in $accessHashTable.Keys) {
                        # Create the permission object per account in the hash table
                        $permissionObject = $Account, $accessHashTable[$Account], "ContainerInherit,ObjectInherit", "None", "Allow"
                        # Create ACL access rule and apply permission object
                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($permissionObject)
                        # Apply the access rule to the ACL Object
                        $aclObject.SetAccessRule($accessRule)
                    } # end foreach loop

                    Write-Debug "check new permissions on acl object"
                    # Apply updated ACL object to ACL Path
                    $initalAclCheck = Compare-Object -ReferenceObject $aclObject.Access -DifferenceObject (Get-Acl -Path $Item.FullName -ErrorAction SilentlyContinue).Access
                    If ($initalAclCheck) {
                        Set-Acl -Path $Item.FullName -AclObject $aclObject -ErrorAction SilentlyContinue
                        
                        # Get newly applied ACL(s)
                        $newAclObject = Get-Acl -Path $Item.FullName -ErrorAction SilentlyContinue
                        
                        Write-Debug ("check new acl object permissions")
                        If ($newAclObject) {
                            # Compare modifed ACL to fetched ACL Object
                            $aclValidation = Compare-Object -ReferenceObject $aclObject.Access -DifferenceObject $newAclObject.Access

                            Write-Debug "check acl validation"
                            If ($aclValidation) { Write-Warning ("ACL(s) on the folder '{0}', were not applied correctly" -f $Item.FullName) }
                            Else { Write-Host ("[SUCCESS] Applied new ACL(s) on folder '{0}'" -f $Item.FullName) -ForegroundColor Green }
                        }
                        Else { Write-Warning ("Unable to get newly applied ACL(s) from folder '{0}'" -f $Item.FullName) }
                    }
                    Else { Write-Host ("[INFO] No change need for ACL(s) on folder '{0}'" -f $Item.FullName) -ForegroundColor Cyan }
                }
                Else { Write-Warning ("Unable to get ACL(s) from folder '{0}'" -f $Item.FullName) }
            }
            Else { Write-Warning ("Unable to location User Account from Active Directory Global Catalog using '{0}'" -f $userName) }
            $i++
        } # end foreach loop
        Write-Progress -Activity "Processing Folders" -Completed
    }
    END {
        $stopWatch.Stop()
        Write-Verbose ("Process Completed in: {0}" -f $stopWatch.Elapsed)
    }
}