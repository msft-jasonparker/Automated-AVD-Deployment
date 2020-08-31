# Automated Deployment of Windows Virtual Desktop

This repo is comprised of a PowerShell module, scripts, Azure ARM templates, and ARM parameter files.  The goal of this repo is to provide any organization looking to deploy Windows Virtual Desktop, an easy to use deployment model based on a set group of standards.

## Requirements

Below are some of the minimum requirements to be able to use this repo in a Test \ Dev \ Prod environment.

### Knowledge

- Intermediate knowledge of PowerShell sytanx, scripts and modules (Advanced is preferred)
- Intermediate knowledge of Azure infrastructure, networking, storage and automation
- Strong understanding of ARM templates and parameters

### Azure

The following resources are considered to be the minimum resources needed to ensure successful deployments along with dynamic scaling.

- Subscription(s)
  - 1 or more Subscriptions (e.g. Core sub, EastUS sub)
- Resource Group(s)
  - 1 x Resource Group for services resources
  - 1 x Resource Group for network resources
  - 1 or more Resource Groups for WVD Host Pools and Session Hosts
    - The naming convention for the Resource Groups is a critical part of the deployment process as it relies on a numeric sequence (e.g. HostPool-RG-1, HostPool-RG-2)
- Network Resource(s)
  - 1 x Virtual Network
    - 1 or more Subnets for each Host Pool
      - The naming convention for the subnets is a critical part of the deployment process as it relies on a numeric sequence and should also correspond with the Resource Groups (e.g. WVD-Subnet-1, WVD-Subnet-2)
- Storage Account(s)
  - 1 x Storage Account
    - 1 x container called dsc
    - 1 x container called templates
- Key Vault(s)
  - 1 x Key Vault
    - Secrets
      - WVD-VM-Admin-Account
      - WVD-VM-Admin-Password
      - WVD-LA-WorkspaceId
      - WVD-LA-WorkspaceKey
      - WVD-VM-DomainJoin-Account
      - WVD-VM-DomainJoin-Password
      - WVD-SessionHost-OU
- Automation Account(s)
  - 1 x Automation Account
    - Run As enabled with contributor level access to all subscriptions
- Log Analytics Workspace(s)
  - 1 x Workspace

### Non-Azure

While these requirements are listed as non-Azure, they could easily be created in Azure.

- File Share(s)
  - 1 x SMB file share for FSLogix Profile Storage
  - 1 x SMB file share for Session Host software package repository
- Code Repositories(s)
  - 1 x repository for deployment code

## Getting Started

To use this repository, first clone or download to your own repository. This will allow your organization to customize the deployment code to suit your specific needs. Alternative, the repository could also be forked in the event updates to this repository need to flow to other repositories.

Next, create the required Azure resources listed in the Requirements section. This should include not only the creation of the resources, but also the configuration of these resources. For example:

- Upload the ARM template and parameter files to the templates container in the Storage Account
- Package the DSC configuration script into an archive
- Upload the DSC configuration archive to the dsc container in the Storage Account
- Import or create the runbooks for Dynamic Scaling

 Update the templates and scripts based on the resources that either exist or were created to support this deployment process. The **Deployment** section will provide the step-by-step process needed to use this automated deployment repository.

## Deployment

 This section will outline the purpose / function for each of the template and parameter files along with which sections should be updated before running a deployment job. The fundamental basis for this deployment process is a series of cascading Resource Group deployments that end with the creation of the Host Pools, Application Groups, Session Hosts, and Availability Sets. The last deployment would define the configuration (Monitoring extension, Domain Join extension, and DSC extension) which ensures the Session Hosts are ready for user load.

### PowerShell Module Dependancies

 Before attempting to use this automated deployment process, ensure the following PowerShell modules have been installed and updated.

- Az Module (and dependancies)
- Az.DesktopVirtualization (should be installed with the Az module)
- Az.WvdOperations.psm1 (located in the Operations folder)

The Az.WvdOperations module was created to be used with this deployment process.  Located in the .\Scripts directory is a script called 'CopyToPSPath.ps1'.  Run this script to copy the module to your path and import to your session.

### Scale Unit ARM Template

 ````.\Deployment\Deploy-WVD-ScaleUnit.json````

A "scale unit" is the term used in reference to a group of Host Pools and Session Hosts which should be deployed to meet a specific scenario. This deployment assumes the necessary planning has been done to determine the number of users per Session Host, the number of Session Hosts per Host Pool and the number of Host Pools needed for deployment.

#### **Variables**

 ````JSON
"copy": [{
    "name": "wvdAppGroupArray",
    "count": "[length(parameters('wvd_hostPoolConfig').configs)]",
    "input": "[resourceId(concat(parameters('wvd_hostPoolResourceGroupPrefix'),add(parameters('wvd_hostPoolInitialValue'),copyIndex('wvdAppGroupArray'))),'Microsoft.DesktopVirtualization/applicationgroups/',concat(parameters('az_cloudResourcePrefix'),'-wvd-hostpool-',padLeft(add(parameters('wvd_hostPoolInitialValue'),copyIndex('wvdAppGroupArray')),2,'0'),'-DAG'))]"
}],
"wvdResourceLocation": "[resourceGroup().location]",
"wvdWorkspaceName": "[concat(parameters('az_cloudResourcePrefix'),'-wvd-workspace')]",
"azDeploymentString": "[parameters('wvd_deploymentString')]"
````

- **wvdAppGroupArray**: This variable is a construct of the *to be* created Desktop Application Groups (DAG).  This is required because if you have any existing DAG(s), writing this array to the WVD workspace will override any previous DAG(s). Later in the template, we'll add this variable to the reference of the existing properties.
- **wvdWorkspaceName**: This variable uses the *az_cloudResourcePrefix* parameter to construct the WVD workspace name. Adjust this variable as needed.

#### **Resources**

The Deploy-WVD-ScaleUnit.json ARM template contains 2 resources, both of which are addition deployments. The first is the Host Pool deployment and the last is the Workspace deployment. The Host Pool deployment uses a linked template URI as the based template and the parameters are defined in line. The Workspace deployment defines the WVD Workspace resource and contains the property section below which defines the DAG(s) linked to it.

````JSON
"properties": {
    "applicationGroupReferences": "[concat(reference(resourceId(parameters('wvd_workspaceResourceGroup'),'Microsoft.DesktopVirtualization/workspaces',variables('wvdWorkspaceName')),'2019-12-10-preview','Full').properties.applicationGroupReferences,variables('wvdAppGroupArray'))]"
}
````

As you can see from the code above, the *applicationGroupReferences* is a combination of the existing references along with the variable above.

#### Outputs

The outputs from this template are important as they provide critical information which is provide to the WVD configuration deployment.

````JSON
"hostPoolsDeployed": {
  "type": "array",
  "copy": {
      "count": "[length(parameters('wvd_hostPoolConfig').configs)]",
      "input": {
          "hostpoolName": "[reference(concat('Deploy-WVD-HostPool-',padLeft(add(parameters('wvd_hostPoolInitialValue'),copyIndex()),2,'0'),'-',variables('azDeploymentString'))).outputs.hostPoolName.value]",
          "resourceGroupName": "[reference(concat('Deploy-WVD-HostPool-',padLeft(add(parameters('wvd_hostPoolInitialValue'),copyIndex()),2,'0'),'-',variables('azDeploymentString'))).outputs.resourceGroupName.value]",
          "deploymentType": "[reference(concat('Deploy-WVD-HostPool-',padLeft(add(parameters('wvd_hostPoolInitialValue'),copyIndex()),2,'0'),'-',variables('azDeploymentString'))).outputs.deploymentType.value]",
          "deploymentFunction": "[parameters('wvd_hostPoolConfig').configs[copyIndex()].deploymentFunction]",
          "dscConfiguration": "[parameters('wvd_hostPoolConfig').configs[copyIndex()].dscConfiguration]",
          "fsLogixVhdLocation": "[parameters('wvd_hostPoolConfig').configs[copyIndex()].fsLogixVhdLocation]",
          "sessionHostNames": "[reference(concat('Deploy-WVD-HostPool-',padLeft(add(parameters('wvd_hostPoolInitialValue'),copyIndex()),2,'0'),'-',variables('azDeploymentString'))).outputs.sessionHostNames.value]"
      }
  }
}
````

- **hostPoolsDeployed**: This output is an array of information based on the number of Host Pools that are deployed. For each Host Pool created, the following outputs are collected:
  - hostPoolName
  - resourceGroupName
  - deploymentType
  - deploymentFunction
  - dscConfiguration
  - fsLogixVhdLocation
  - sessionHostNames

