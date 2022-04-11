Function New-AzAvdCoreResources {
    [CmdletBinding()]
    Param (
        # Name of the Resource Group where the Core Resources should be deployed (supports tab completion)
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceGroupCompleterAttribute()]
        [System.String]$ResourceGroupName
    )
    BEGIN {
        #Requires -Modules @{ModuleName="Az.DesktopVirtualization"; ModuleVersion="2.0.0"}
        Show-Menu -Title $PSCmdlet.MyInvocation.MyCommand.Name -Style Info -Color White -DisplayOnly
        Get-AzAuthentication
        Write-Verbose ("{0} - AzAuthentication - {1} Connected to {2} ({3})" -f (Get-Date).ToLongTimeString(),$SCRIPT:AzAuthentication.Account.Id,$SCRIPT:AzAuthentication.Subscription.Name,$SCRIPT:AzAuthentication.Subscription.Id)
        
        $avdWorkspace = Get-AzWvdWorkspace -ResourceGroupName $ResourceGroupName
        If ($avdWorkspace) { Write-Host ("INFO:    {0} - Found valid Azure Virtual Desktop workspace ({1})" -f (Get-Date).ToLongTimeString(),$avdWorkspace.Name) }
        Else {
            Write-Verbose ("{0} - Azure Virtual Desktop Workspace not found!" -f (Get-Date).ToLongTimeString())
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::New(
                    [System.SystemException]::New(("Workspace not found in {1}" -f $SCRIPT:AzAuthentication.Subscription.Name)),
                    "WorkspaceNotFoundInResourceGroup",
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    ("AVD Workspace Object")
                )
            )
        }

        Write-Verbose ("{0} - Selecting AVD Core Resources ARM Template and Parameters file" -f (Get-Date).ToLongTimeString())
        Show-Menu -Title "Select AVD Core Resources ARM Template" -Style Info -Color Cyan -DisplayOnly
        $coreResourcesTemplate = Get-FileNameDialog -Filter "Json Files (*.json)|*.json|Bicep Files (*.bicep)|*.bicep"
        Show-Menu -Title "Select AVD Core Resources ARM Parameter File" -Style Info -Color Cyan -DisplayOnly
        $coreResourcesParameters = Get-FileNameDialog -Filter "Json Files (*.json)|*.json|Bicep Files (*.bicep)|*.bicep"
        If ([system.string]::IsNullOrEmpty($coreResourcesTemplate) -OR [system.string]::IsNullOrEmpty($coreResourcesParameters)) {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::New(
                    [System.SystemException]::New(("One or more Core Resource files were not selected!")),
                    "TemplateFilesNotFound",
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    ("AVD Core Resource Templates")
                )
            )
        }
        Else {
            $correlationId = [Guid]::NewGuid().ToString()
            Write-Verbose ("{0} - TemplateFile: $coreResourcesTemplate" -f (Get-Date).ToLongTimeString())
            Write-Verbose ("{0} - ParameterFile: $coreResourcesParameters" -f (Get-Date).ToLongTimeString())
            Write-Verbose ("{0} - Deployment String: $correlationId" -f (Get-Date).ToLongTimeString())
        }
    }
    PROCESS {
        try {
            Write-Verbose ("{0} - Deploying AVD Core Resources from selected template and parameter files" -f (Get-Date).ToLongTimeString())
            $Results = New-AzResourceGroupDeployment `
                -Name ("ACS-CoreResources-Deployment-{0}" -f $correlationId.Split("-")[-1]) `
                -ResourceGroupName $ResourceGroupName `
                -TemplateFile $coreResourcesTemplate `
                -TemplateParameterFile $coreResourcesParameters

            Write-Verbose ("{0} - The ACS-AVD-CoreResources-Deployment-{1} deployment completed successfully!" -f (Get-Date).ToLongTimeString(),$correlationId.Split("-")[-1])
            Write-Verbose ("{0} - Updating the {1} AVD Workspace with the newly created Application Groups" -f (Get-Date).ToLongTimeString(),$avdWorkspace.Name)
            
            Write-Host ("INFO:    {0} - Current Application Groups: {1} | New Application Groups: {2}" -f (Get-Date).ToLongTimeString(),$avdWorkspace.ApplicationGroupReference.Count,$Results.Outputs["avdAppGroupIds"].Value.Count)
            $success = 0
            [PSCustomObject]$Output = $Results.Outputs["avdCoreProperties"].Value.ToString() | ConvertFrom-Json
            $OutputHash = $Output | Group-Object -Property avdHostPoolName -AsHashTable -AsString
            
            $i = 1
            Foreach ($HostPool in $OutputHash.Keys) {
                #$DebugPreference = "Inquire"
                #Write-Debug "Check Loop #$i"
                $workspaceResult = $null
                $workspaceResult = Register-AzWvdApplicationGroup -ResourceGroupName $ResourceGroupName -WorkspaceName $avdWorkspace.Name -ApplicationGroupPath $OutputHash[$HostPool].avdAppGroupId -ErrorAction SilentlyContinue

                If ($avdWorkspace.ApplicationGroupReference -contains $OutputHash[$HostPool].avdAppGroupId){
                    Write-Host ("`tApplication Group: {0}`t FOUND" -f $OutputHash[$HostPool].avdAppGroupId.Split("/")[-1]) -ForegroundColor Cyan
                    Write-Host ("`tHost Pool: {0} | Updating Desktop Application Group Friendly Name..." -f $HostPool)
                    Update-AzWvdDesktop -ResourceGroupName $ResourceGroupName -ApplicationGroupName $OutputHash[$HostPool].avdAppGroupId.Split("/")[-1] -Name SessionDesktop -FriendlyName ("{0}-{1}-{2}-Desktop" -f $OutputHash[$HostPool].azEnvironment,$OutputHash[$HostPool].azProgram,$OutputHash[$HostPool].avdWorkload) | Out-Null
                }
                ElseIf ($workspaceResult.ApplicationGroupReference -contains $OutputHash[$HostPool].avdAppGroupId) {
                    Write-Host ("`tApplication Group: {0}`t ADDED" -f $OutputHash[$HostPool].avdAppGroupId.Split("/")[-1]) -ForegroundColor Green
                    Write-Host ("`tHost Pool: {0} | Updating Desktop Application Group Friendly Name" -f $HostPool)
                    Update-AzWvdDesktop -ResourceGroupName $ResourceGroupName -ApplicationGroupName $OutputHash[$HostPool].avdAppGroupId.Split("/")[-1] -Name SessionDesktop -FriendlyName ("{0}-{1}-{2}-Desktop" -f $OutputHash[$HostPool].azEnvironment,$OutputHash[$HostPool].azProgram,$OutputHash[$HostPool].avdWorkload) | Out-Null
                    $success++
                }
                Else { Write-Host ("`tApplication Group: {0}`t FAILED" -f $OutputHash[$HostPool].avdAppGroupId.Split("/")[-1]) -ForegroundColor Yellow }
                $i++
            }
        }
        catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
    }
    END {
        #Write-Debug "check end"
        Write-Host ("INFO:    {0} - Successfully Added: {1} Applications Groups to the {2} Workspace" -f (Get-Date).ToLongTimeString(),$success,$avdWorkspace.Name)
        #$DebugPreference = "SilentlyContinue"
    }
}