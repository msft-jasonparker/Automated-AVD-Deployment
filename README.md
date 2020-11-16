# Automated Deployment of Windows Virtual Desktop

This repo is comprised of a PowerShell module (Az.WvdOperations), Azure ARM templates, Azure ARM template parameter files, and Desired State Configuration scripts.  The goal of this repo is to provide any organization looking to deploy Windows Virtual Desktop, an easy to use deployment model based on a set group of standards.

> **WARNING:**
> 
> This repo assumes that you or your organization is already well established into Microsoft Azure. There are many dependencies required to make this repo / solution to work correctly. The requirements section below should outline what is required for this repo to be successfully deployed.

---

## Table of Contents

- [Automated Deployment of Windows Virtual Desktop](#automated-deployment-of-windows-virtual-desktop)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
    - [Knowledge](#knowledge)
    - [Azure](#azure)
    - [Non-Azure](#non-azure)
  - [Azure Setup - Greenfield Deployments](#azure-setup---greenfield-deployments)
  - [Getting Started](#getting-started)
  - [Deployment](#deployment)
    - [PowerShell Module Dependencies](#powershell-module-dependencies)
    - [Scale Unit ARM Template](#scale-unit-arm-template)
      - [**Scale Unit Variables**](#scale-unit-variables)
      - [**Scale Unit Resources**](#scale-unit-resources)
      - [**Scale Unit Outputs**](#scale-unit-outputs)
    - [Scale Unit Parameter File](#scale-unit-parameter-file)
    - [Host Pool ARM Template](#host-pool-arm-template)
      - [**Host Pool Functions**](#host-pool-functions)
      - [**Host Pool Variables**](#host-pool-variables)
      - [**Host Pool Resources**](#host-pool-resources)
      - [**Host Pool Outputs**](#host-pool-outputs)
    - [Session Host ARM Template](#session-host-arm-template)
      - [**Session Host Functions**](#session-host-functions)
      - [**Session Host Variables**](#session-host-variables)
      - [**Session Host Resources**](#session-host-resources)
      - [**Session Host Outputs**](#session-host-outputs)
    - [WVD Configuration ARM Template](#wvd-configuration-arm-template)
      - [**Configuration Variables**](#configuration-variables)
      - [**Configuration Resources**](#configuration-resources)
  - [Desired State Configuration (Session Host Customization)](#desired-state-configuration-session-host-customization)

## Requirements

Below are some of the minimum requirements to be able to use this repo in a Test \ Dev \ Prod environment.

---

### Knowledge

- Intermediate knowledge of PowerShell syntax, scripts, and modules (Advanced is preferred)
- Intermediate knowledge of Azure infrastructure, networking, storage, and automation
- Strong understanding of ARM templates and parameters

---

### Azure

The following resources are considered to be the minimum resources needed to ensure successful deployments along with dynamic scaling. Manually create the required components or use the [Azure Setup](#azure-setup---greenfield-deployments) templates

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

---

### Non-Azure

While these requirements are listed as non-Azure, they could easily be created in Azure.

- File Share(s)
  - 1 x SMB file share for FSLogix Profile Storage
  - 1 x SMB file share for Session Host software package repository
- Code Repositories(s)
  - 1 x repository for deployment code

---

## Azure Setup - Greenfield Deployments

If you are looking to test this repo in a dev / test environment, use the links below to create the framework required for a successful deployment.

Creates the following Azure Components:
  - Resource Groups:
    - WVD-NET-RG (Networking Resources)
    - WVD-SVCS-RG (Shared Services Resources)
    - WVD-POOL-RG-01 (Host Pool Resources)
    - WVD-POOL-RG-02 (Host Pool Resources)
  - Resources:
    - WVD-VNET (Virtual Network - 192.168.0.0/16)
      - WVD-Subnet-00 (Shared Services subnet - 192.168.0.0/24)
      - WVD-Subnet-01 (Host Pool 01 subnet - 192.168.1.0/24)
      - WVD-Subnet-02 (Host Pool 02 subnet - 192.168.2.0/24)
    - WVD-KV-(uniqueString)
      - Secrets:
        - WVD-VM-Admin-Account
        - WVD-VM-Admin-Password
        - WVD-LA-WorkspaceId
        - WVD-LA-WorkspaceKey
        - WVD-VM-DomainJoin-Account
        - WVD-VM-DomainJoin-Password
        - WVD-SessionHost-OU
    - WVD-AA-(uniqueString) (Automation Account)
    - WVD-LA-(uniqueString) (Log Analytics Workspace)
    - wvdartifacts(uniquestring) (Storage Account)
      - Blob container(s): dsc,templates

[![Deploy To Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fmsft-jasonparker%2FAutomated-WVD-Deployment%2Fmaster%2FSetup%2FDeploy-WVD-Foundation.json)
[![Deploy To Azure US Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fmsft-jasonparker%2FAutomated-WVD-Deployment%2Fmaster%2FSetup%2FDeploy-WVD-Foundation.json)

---

## Getting Started

To use this repository, first clone or download to your own repository. This will allow your organization to customize the deployment code to suit your specific needs. Alternative, the repository could also be forked in the event updates to this repository need to flow to other repositories.

Open a PowerShell console and navigate to the '*Scripts*' sub-directory of the repository.  If not already done, run ```Set-ExecutionPolicy Bypass``` from an administrator console. From the '*Scripts*' sub-directory run the ```CopyToPSPath.ps1``` script which will copy the Az.WvdOperations Module into your modules directory (All Users) and then imports the module to your PowerShell session. Discover the commands in the function by typing, ```Get-Command -Module Az.WvdOperations```. If you need more information about a specific command, use ```Get-Help <cmd> -Detailed```.

Next, create the required Azure resources listed in the Requirements section. This should include not only the creation of the resources, but also the configuration of these resources. For example:

- Upload the ARM template and parameter files to the templates container in the Storage Account
- Package the DSC configuration script into an archive and upload to a Storage Account
- Upload the DSC configuration archive to the dsc container in the Storage Account
- Import or create the runbooks for Dynamic Scaling

 Update the templates and scripts based on the resources that either exist or were created to support this deployment process. The **Deployment** section will provide the step-by-step process needed to use this automated deployment repository.

---

## Deployment

 This section will outline the purpose / function for each of the template and parameter files along with which sections should be updated before running a deployment job. The fundamental basis for this deployment process is a series of cascading Resource Group deployments that end with the creation of the Host Pools, Application Groups, Session Hosts, and Availability Sets. The last deployment would define the configuration (Monitoring extension, Domain Join extension, and DSC extension) which ensures the Session Hosts are ready for user load.

---

### PowerShell Module Dependencies

 Before attempting to use this automated deployment process, ensure the following PowerShell modules have been installed and updated.

- Az Module (and dependancies)
- Az.DesktopVirtualization (should be installed with the Az module)
- Az.WvdOperations.psm1 (located in the Operations folder)

---

### Scale Unit ARM Template

 `.\Deployment\Deploy-WVD-ScaleUnit.json`

A "scale unit" is the term used in reference to a group of Host Pools and Session Hosts which should be deployed to meet a specific scenario. This deployment assumes the necessary planning has been done to determine the number of users per Session Host, the number of Session Hosts per Host Pool and the number of Host Pools needed for deployment.

#### **Scale Unit Variables**

 ```JSON
"copy": [{
  "name": "wvdAppGroupArray",
  "count": "[length(parameters('wvd_hostPoolConfig').configs)]",
  "input": "[resourceId(concat(parameters('wvd_hostPoolResourceGroupPrefix'),padleft(add(parameters('wvd_hostPoolInitialValue'),copyIndex('wvdAppGroupArray')),2,'0')),'Microsoft.DesktopVirtualization/applicationgroups/',concat(parameters('az_cloudResourcePrefix'),'-wvd-hostpool-',padLeft(add(parameters('wvd_hostPoolInitialValue'),copyIndex('wvdAppGroupArray')),2,'0'),'-DAG'))]"
}],
"wvdResourceLocation": "[resourceGroup().location]",
"wvdWorkspaceName": "[concat(parameters('az_cloudResourcePrefix'),'-wvd-workspace')]",
"azDeploymentString": "[parameters('wvd_deploymentString')]"
```

- **wvdAppGroupArray**: This variable is a construct of the *to be* created Desktop Application Groups (DAG).  This is required because if you have any existing DAG(s), writing this array to the WVD workspace will override any previous DAG(s). Later in the template, we'll add this variable to the reference of the existing properties.
- **wvdWorkspaceName**: This variable uses the *az_cloudResourcePrefix* parameter to construct the WVD workspace name. Adjust this variable as needed.

> IMPORTANT!
>
> The Windows Virtual Desktop Workspace **must** exist prior to any Scale Unit deployment.

#### **Scale Unit Resources**

The Deploy-WVD-ScaleUnit.json ARM template contains 2 resources, both of which are deployments and not direct resources. The first is the Host Pool deployment and the last is the Workspace deployment. The Host Pool deployment uses a linked template URI as the based template and the parameters are defined in line. The Workspace deployment defines the WVD Workspace resource and contains the property section below which defines the DAG(s) linked to it.

```JSON
"properties": {
  "applicationGroupReferences": "[concat(reference(resourceId(parameters('wvd_workspaceResourceGroup'),'Microsoft.DesktopVirtualization/workspaces',variables('wvdWorkspaceName')),'2019-12-10-preview','Full').properties.applicationGroupReferences,variables('wvdAppGroupArray'))]"
}
```

As you can see from the code above, the *applicationGroupReferences* is a combination of the existing references along with the variable above.

#### **Scale Unit Outputs**

The outputs from this template are important as they provide critical information which is provide to the WVD configuration deployment.

```JSON
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
```

- **hostPoolsDeployed**: This output is an array of information based on the number of Host Pools that are deployed. For each Host Pool created, the following outputs are collected:
  - hostPoolName
  - resourceGroupName
  - deploymentType
  - deploymentFunction
  - dscConfiguration
  - fsLogixVhdLocation
  - sessionHostNames (broken)

---

### Scale Unit Parameter File

`.\Deployment\Deploy-WVD-ScaleUnit.parameters.json`

The parameter file is the main engine which drives the deployment of the "scale unit".  Each of the parameters in the file have metadata descriptions to aide in understand each of the parameters intended purpose.  Below is the detail information for the *wvd_hostPoolConfig* parameter, which is an object.

```JSON
"wvd_hostPoolConfig": {
  "value": {
    "configs": [
      {
        "deploymentType": "PROD",
        "deploymentFunction": "VDI",
        "fsLogixVhdLocation": "\\\\<SERVERNAME>\\<SHARENAME>\\%userdomain%",
        "dscConfiguration": "WVD-Win10-SessionHost-Config.ps1.zip",
        "wvdArtifactLocation": "\\\\<SERVERNAME>\\<SHARENAME>\\wvdartifacts",
        "azVmNumberOfInstances": 6,
        "azVmStartingIncrement": 1
      },
      {
        "deploymentType": "PROD",
        "deploymentFunction": "VDI",
        "fsLogixVhdLocation": "\\\\<SERVERNAME>\\<SHARENAME>\\%userdomain%",
        "dscConfiguration": "WVD-Win10-SessionHost-Config.ps1.zip",
        "wvdArtifactLocation": "\\\\<SERVERNAME>\\<SHARENAME>\\wvdartifacts",
        "azVmNumberOfInstances": 6,
        "azVmStartingIncrement": 1
      }
    ]
  },
  "metadata": {
    "description": "Update this value to reflect the number of Host Pools to create, the type Host Pool it will serve and the location of the FSLogix profiles. Each config is a host pool with the number of VMs"
  }
},
```

Each section under `"configs":` is a unique Host Pool which will be deployed.  Within each config are a set of parameters which the Host Pool needs for proper deployment.

- **deploymentType**: This value can be used in DSC configurations to allow for each Host Pool to drive a unique DSC configuration or install a different set of applications. For example, if you wanted to have a Host Pool for BYOD devices and a Host Pool for CORP devices and the Session Hosts needed unique configurations.
- **deploymentFunction**: This value can also be used in DSC configurations to allow for unique configurations. For example, if you wanted to have a Host Pool that was geared for IT Operations and the tools they needed, you could set this value to *ADMIN*.
- **fsLogixVhdLocation**: This is the file share path for profile containers created by FSLogix.
- **dscConfiguration**: This is the name of the DSC configuration archive (zip) used to configure the Session Hosts.
- **azVMNumberOfInstances**: This *SHOULD* be an even number as it will split this number based on the number of groups defined by *wvd_groupReference* and is the total number of Session Hosts for the Host Pool.

---

### Host Pool ARM Template

`.\Deployment\LinkedTemplates\Deploy-WVD-HostPool.json`

The Host Pool ARM Template is responsible for the creation of the WVD Host Pool, Desktop Application Group (DAG), Availability Sets, and the deployment of the Session Hosts. The Host Pool and DAG are single item resources, but the Availability Sets and Session Hosts have copy counts based on *wvd_groupReference* parameter which was defined in the `Deploy-WVD-ScaleUnit.parameters.json` file. Below you'll find details about the different secions of the ARM template and the areas which should be reviewed for a more customized deployment.

#### **Host Pool Functions**

Functions are used to construct resource names based on a predefined set of parameters. This template has a function which creates the Host Pool name and a function for building the inital Session Host prefix.

```JSON
{
  "namespace": "wvdHostPool",
  "members": {
    "getName": {
      "parameters": [
        {
          "name": "RegionPrefix",
          "type": "string"
        },
        {
          "name": "HostPoolIncrement",
          "type": "int"
        }
      ],
      "output": {
        "type": "string",
        "value": "[toLower(concat(parameters('RegionPrefix'),'-wvd-hostpool-',padLeft(parameters('HostPoolIncrement'),2,'0')))]"
      }
    }
  }
},
{
  "namespace": "wvdSessionHost",
  "members": {
    "getName": {
      "parameters": [
        {
          "name": "SessionHostGroupPrefix",
          "type": "string"
        },
        {
          "name": "HostPoolIncrement",
          "type": "int"
        }
      ],
      "output": {
        "type": "string",
        "value": "[toLower(concat(parameters('SessionHostGroupPrefix'),'-wshp',padLeft(parameters('HostPoolIncrement'),2,'0')))]"
      }
    }
  }
}
```

- **wvdHostPool**: Takes two (2) input parameters (region prefix and host pool increment value) and constructs the Host Pool name. For example, if the region prefix was '*azeus*' and the host pool increment number was 3, the Host Pool name would be '**azeus-wvd-hostpool-03**'.
- **wvdSessionHost**: Takes two (2) input parameters (session host prefix and host pool increment value) and constructs the **initial** Session Host name prefix.  This prefix is used later in the `.\Deployment\LinkedTemplates\Deploy-WVD-SessionHosts.json` template. For example, if the prefix was '*eus*' and the host pool increment number was 3, the Session Host prefix would be '**eus-wshp03**'. The prefix should be at most 3 characters to ensure a computer name of no more than 15 characters.

> NOTE: These functions can be modified to suit any organizational naming standards. Keep in mind the Session Hosts are computer accounts and must be less than 15 characters. This deployment scheme creates Host Pool and Session Host names as follows:
>
> - Host Pool: `<prefix>`-wvd-hostpool-`<increment value>`
> - Session Host: `<prefix>`-wshp`<increment value>`

#### **Host Pool Variables**

```JSON
{
  "wvdHostPoolTokenExpirationTime": "[dateTimeAdd(parameters('timeStamp'), 'PT23H')]",
  "createVMs": "[greater(parameters('az_vmNumberOfInstances'),0)]",
  "wvdHostPoolName": "[wvdHostPool.getName(parameters('az_cloudResourcePrefix'),parameters('wvd_hostPoolIncrement'))]",
  "wvdshPrefix": "[wvdSessionHost.getName(parameters('az_wkstaPrefix'),parameters('wvd_hostPoolIncrement'))]",
  "wvdSubnetName": "[concat(parameters('vn_virtualNetworkSubnetPrefix'),padLeft(parameters('wvd_hostPoolIncrement'),2,'0'))]",
  "wvdSubnetId": "[resourceId(parameters('vn_virtualNetworkResourceGroupName'),'Microsoft.Network/virtualNetworks/subnets',parameters('vn_virtualNetworkName'), variables('wvdSubnetName'))]",
  "wvdVMTemplate": "[concat(
      '{\"domain\":\"',
      parameters('domain'),
      '\",\"galleryImageOffer\":\"',
      parameters('az_vmImageOffer'),
      '\",\"galleryImagePublisher\":\"',
      parameters('az_vmImagePublisher'),
      '\",\"galleryImageSKU\":\"',
      parameters('az_vmImageSKU'),
      '\",\"imageType\":\"Gallery\"',
      ',\"imageUri\":null',
      ',\"customImageId\":null',
      ',\"namePrefix\":\"',
      variables('wvdshPrefix'),
      '\",\"osDiskType\":\"',
      parameters('az_vmDiskType'),
      '\",\"useManagedDisks\":true',
      ',\"vmSize\":{\"id\":\"',
      parameters('az_vmSize'),
      '\",\"cores\":8,\"ram\":32}}')]",
  "wvdResourceLocation": "[resourceGroup().location]",
  "wvdResourceGroupName": "[resourceGroup().name]",
  "wvdSessionHostInstances": "[div(parameters('az_vmNumberOfInstances'),length(parameters('wvd_groupReference')))]"
}
```

- **wvdHostPoolTokenExpirationTime**: Creates a date / time value 23 hours in the future as the expiration time of the Host Pool registration token
- **createVMs**: True / False value used as a condition to create Availability Sets and Virtual Machines.
- **wvdHostPoolName**: Calls the wvdHostPool function to construct the Host Pool name.
- **wvdshPrefix**: Calls the wvdSessionHost function to construct the Session Host prefix.
- **wvdSubnetName**: Creates the subnet name based on Host Pool increment value.
- **wvdSubnetId**: Required variable used in the Session Host deployment process.
- **wvdVMTemplate**: JSON escaped string which ensures the Host Pool has a defined VM template in order to support adding Session Hosts to the Host Pool.
- **wvdResourceLocation**: Specifies the Azure region for the WVD resources.
- **wvdResourceGroupName**: Speifis the Azure Resource Group for the WVD resources.
- **wvdSessionHostInstances**: Uses the provided number of instances and divides the number by the length of the 'wvd_groupReference' parameter (should be 2).

#### **Host Pool Resources**

Below are the resources deployed as part of the Host Pool ARM template.

- **Host Pool**: 

  ````JSON
  {
    "type": "Microsoft.DesktopVirtualization/hostpools",
    "apiVersion": "[parameters('wvd_apiVersion')]",
    "name": "[variables('wvdHostPoolName')]",
    "location": "[variables('wvdResourceLocation')]",
    "tags": {
        "WVD-Maintenance": "True",
        "WVD-Build": "[parameters('wvd_buildVersion')]",
        "WVD-Deployment": "[parameters('wvd_deploymentType')]",
        "WVD-Function": "[parameters('wvd_deploymentPurpose')]",
        "WVD-DscConfiguration": "[parameters('wvd_dscConfiguration')]",
        "WVD-FsLogixVhdLocation": "[parameters('wvd_FsLogixVhdLocation')]"
    },
    "properties": {
        "friendlyName": "[concat('WVD Host Pool ',padLeft(parameters('wvd_hostPoolIncrement'),2,'0'),' (',toUpper(parameters('wvd_deploymentType')),' v',parameters('wvd_buildVersion'),')')]",
        "hostpoolType": "Pooled",
        "description": "[concat(
            '{\"DscConfiguration\":\"',
            parameters('wvd_dscConfiguration'),
            '\",\"FsLogixVhdLocation\":\"',
            parameters('wvd_fsLogixVhdLocation'),
            '\",\"ImagePublisher\":\"',
            parameters('az_vmImagePublisher'),'\"}'
        )]",
        "customRdpProperty": "[parameters('wvd_customRdpProperty')]",
        "maxSessionLimit": "[parameters('wvd_maxSessionLimit')]",
        "loadBalancerType": "[parameters('wvd_loadBalancerType')]",
        "ring": null,
        "registrationInfo": {
            "expirationTime": "[variables('wvdhostPoolTokenExpirationTime')]",
            "token": null,
            "registrationTokenOperation": "Update"
        },
        "vmTemplate": "[variables('wvdVMTemplate')]"
    }
  }
  ````

- **Desktop Application Group (DAG)**:

  ````JSON
  {
    "type": "Microsoft.DesktopVirtualization/applicationgroups",
    "apiVersion": "[parameters('wvd_apiVersion')]",
    "name": "[concat(variables('wvdHostPoolName'),'-DAG')]",
    "location": "[variables('wvdResourceLocation')]",
    "properties": {
        "hostpoolarmpath": "[resourceId('Microsoft.DesktopVirtualization/hostpools/', variables('wvdHostPoolName'))]",
        "friendlyName": "[concat('vDesktop [',padLeft(parameters('wvd_hostPoolIncrement'),2,'0'),']')]",
        "description": "",
        "applicationGroupType": "Desktop"
    },
    "dependsOn": [
        "[resourceId('Microsoft.DesktopVirtualization/hostpools/', variables('wvdHostPoolName'))]"
    ]
  }
  ````

- **Availability Sets**:

  ````JSON
  {
    "apiVersion": "2019-07-01",
    "type": "Microsoft.Compute/availabilitySets",
    "name": "[concat(variables('wvdHostPoolName'),'-AVSet-',parameters('wvd_groupReference')[copyIndex()])]",
    "location": "[variables('wvdResourceLocation')]",
    "condition": "[variables('createVMs')]",
    "copy": {
        "name": "WVD-Availability-Set",
        "count": "[length(parameters('wvd_groupReference'))]"
    },
    "properties": {
        "platformFaultDomainCount": "[if(greater(length(parameters('wvd_groupReference')),3),3,length(parameters('wvd_groupReference')))]",
        "platformUpdateDomainCount": "[if(greater(variables('wvdSessionHostInstances'),20),20,variables('wvdSessionHostInstances'))]"
    },
    "sku": {
        "name": "Aligned"
    } 
  }
  ````

- **Session Host Deployment**:

  ````JSON
  {
    "apiVersion": "2019-10-01",
    "name": "[concat('Deploy-WVD-SessionHosts-Group-',parameters('wvd_groupReference')[copyIndex()],'-',parameters('az_deploymentString'))]",
    "type": "Microsoft.Resources/deployments",
    "condition": "[variables('createVMs')]",
    "resourceGroup": "[variables('wvdResourceGroupName')]",
    "copy": {
        "name": "WVD-SessionHost-Loop",
        "count": "[length(parameters('wvd_groupReference'))]"
    },
    "dependsOn": [
    ],
    "properties": {
        "mode": "Incremental",
        "templateLink": {
            "uri": "[parameters('wvd_sessionHostTemplateUri')]",
            "contentVersion": "1.0.0.0"
        },
        "parameters": {
          Truncated, see actual template
        }
    }
  }
  ````

#### **Host Pool Outputs**

The outputs from the Host Pool ARM template are passed up the template chain to the Scale Unit.

````JSON
{
  "hostPoolName": {
      "type": "string",
      "value": "[variables('wvdHostPoolName')]"
  },
  "resourceGroupName": {
      "type": "string",
      "value": "[variables('wvdResourceGroupName')]"
  },
  "deploymentType": {
      "type": "string",
      "value": "[parameters('wvd_deploymentType')]"
  },
  "sessionHostNames": {
      "type": "array",
      "copy": {
          "count": "[length(parameters('wvd_groupReference'))]",
          "input": "[reference(concat('Deploy-WVD-SessionHosts-Group-',parameters('wvd_groupReference')[copyIndex()],'-',parameters('az_deploymentString'))).outputs.sessionHostNames.value]"
      }
  }
}
````

- **hostPoolName**: Name of the Host Pool deployed
- **resourceGroupName**: Name of the Resource Group the Host Pool is deployed into
- **deploymentType**: Free form value for the deployment type
- **sessionHostNames**: Array of Session Host names which are derived from the down level Session Host deployment job

---

### Session Host ARM Template

`.\Deployment\LinkedTemplates\Deploy-WVD-SessionHosts.json`

`.\Deployment\LinkedTemplates\Deploy-WVD-SessionHosts.parameters.json`

The Session Host ARM template is responsible for the creation of the Azure virtual machines and their associated resources. This template will create a standard virtual network interface and a virtual machine. The ARM template receives 90% of the parameters from the Host Pool template (in-line), but does have an associated `Deploy-WVD-SessionHosts.parameters.json` file containing references to secrets in the Key Vault.

#### **Session Host Functions**

Functions are used to construct resource names based on a predefined set of parameters. This template has a function which creates the Session Host names.

````JSON
{
  "namespace": "wvdSessionHost",
  "members": {
    "getName": {
      "parameters": [
        {
          "name": "wvdshPrefix",
          "type": "string"
        },
        {
          "name": "sessionHostIncrement",
          "type": "int"
        }
      ],
      "output": {
        "type": "string",
        "value": "[toLower(concat(parameters('wvdshPrefix'),'sh',padLeft(parameters('sessionHostIncrement'),3,'0')))]"
      }
    }
  }
}
````

- **wvdSessionHost**: Takes two (2) input parameters (session host prefix and session host increment) and constructs the name for each Session Host.

#### **Session Host Variables**

````JSON
{
  "azVmAvSetName": "[concat(parameters('wvd_hostpoolName'),'-AVSet-',parameters('wvd_groupReference'))]",
  "storageAccountType": "[parameters('az_vmDiskType')]",
  "wvdResourceLocation": "[resourceGroup().location]",
  "wvdshOffSet": "[if(equals(parameters('wvd_groupReference'),'A'),1,add(parameters('az_vmNumberOfInstances'),1))]"
}
````

- **azVmAvSetName**: Defines the Availability Set name based on the group reference.
- **storageAccountType**: Defines the Storage Account Type as a variable.
- **wvdResourceLocation**: Defines the Azure region for the resources.
- **wvdshOffSet**: Defines the starting value of the copy index for each of the resources. If the group reference equals 'A', then start with the number 1, otherwise use the number of instances and add 1 to it. This ensures that Session Hosts in group B will always be in the last half of the total resource count.

#### **Session Host Resources**

- **Network Interface**:
  
  ````JSON
  {
    "apiVersion": "2019-07-01",
    "type": "Microsoft.Network/networkInterfaces",
    "name": "[concat(wvdSessionHost.getName(parameters('az_vmNamePrefix'),copyIndex(variables('wvdshOffSet'))),'-nic-',parameters('timeStamp'))]",
    "location": "[variables('wvdResourceLocation')]",
    "copy": {
      "name": "WVD-SH-nic-loop",
      "count": "[parameters('az_vmNumberOfInstances')]"
    },
    "properties": {
      "ipConfigurations": [
        {
          "name": "ipconfig",
          "properties": {
            "privateIPAllocationMethod": "Dynamic",
            "subnet": {
              "id": "[parameters('wvd_subnetId')]"
            }
          }
        }
      ],
      "enableAcceleratedNetworking": true
    },
    "dependsOn": [
    ]
  }
  ````

- **Virtual Machine**:

  ````JSON
  {
    "apiVersion": "2019-07-01",
    "type": "Microsoft.Compute/virtualMachines",
    "name": "[wvdSessionHost.getName(parameters('az_vmNamePrefix'),copyIndex(variables('wvdshOffSet')))]",
    "location": "[variables('wvdResourceLocation')]",
    "tags": {
      "WVD-Maintenance": "True",
      "WVD-Build": "[parameters('wvd_buildVersion')]",
      "WVD-Group": "[parameters('wvd_groupReference')]"
    },
    "copy": {
      "name": "WVD-SH-VM-Loop",
      "count": "[parameters('az_vmNumberOfInstances')]"
    },
    "dependsOn": [
      "[resourceId('Microsoft.Network/networkInterfaces',concat(wvdSessionHost.getName(parameters('az_vmNamePrefix'),copyIndex(variables('wvdshOffSet'))),'-nic-',parameters('timeStamp')))]"
    ],
    "properties": {
      "hardwareProfile": {
        "vmSize": "[parameters('az_vmSize')]"
      },
      "osProfile": {
        "computerName": "[wvdSessionHost.getName(parameters('az_vmNamePrefix'),copyIndex(variables('wvdshOffSet')))]",
        "adminUsername": "[parameters('az_vmAdminAccount')]",
        "adminPassword": "[parameters('az_vmAdminAccountPassword')]",
        "windowsConfiguration": {
          "timeZone": "Eastern Standard Time"
        }
      },
      "storageProfile": {
        "imageReference": {
          "publisher": "[parameters('az_vmImagePublisher')]",
          "offer": "[parameters('az_vmImageOffer')]",
          "sku": "[parameters('az_vmImageSKU')]",
          "version": "latest"
        },
        "osDisk": {
          "createOption": "FromImage",
          "name": "[concat(wvdSessionHost.getName(parameters('az_vmNamePrefix'),copyIndex(variables('wvdshOffSet'))),'-osDisk-',parameters('timeStamp'))]",
          "managedDisk": {
            "storageAccountType": "[variables('storageAccountType')]"
          }
        }
      },
      "networkProfile": {
        "networkInterfaces": [
          {
            "id": "[resourceId('Microsoft.Network/networkInterfaces',concat(wvdSessionHost.getName(parameters('az_vmNamePrefix'),copyIndex(variables('wvdshOffSet'))),'-nic-',parameters('timeStamp')))]"
          }
        ]
      },
      "availabilitySet": {
        "id": "[resourceId('Microsoft.Compute/availabilitySets',variables('azVmAvSetName'))]"
      },
      "diagnosticsProfile": {
        "bootDiagnostics": {
          "enabled": false
        }
      },
      "licenseType": "Windows_Client"
    }
  }
  ````

#### **Session Host Outputs**

The outputs from the Session Host ARM template are only the names of the Session Hosts.  This is the first of all the outputs which are passed back up through the initiating ARM templates and ultimately end up as an output of the `Deploy-WVD-Scale-Unit.json` ARM template.

````JSON
{
  "sessionHostNames": {
    "type": "array",
    "copy": {
      "count": "[parameters('az_vmNumberOfInstances')]",
      "input": "[reference(wvdSessionHost.getName(parameters('az_vmNamePrefix'),copyIndex(variables('wvdshOffSet')))).osProfile.computerName]"
    }
  }
}
````

---

### WVD Configuration ARM Template

`.\Deployment\LinkedTemplates\Deploy-WVD-Config.json`

`.\Deployment\LinkedTemplates\Deploy-WVD-Config.parameters.json`

The WVD Configuration ARM template is a completely separated process from the initial WVD resource deployment process. This is intentional so that any issues that arise during the configuration, doesn't cause the resource deployments to fail or report as a false positive. The purpose of this configuration process is to ensure each Session Host is setup with the Azure Dependency Agent, Microsoft Monitoring Agent, Active Directory Domain Join Extension, and the Desired State Configuration extension.  Each of these play an important role in the overall WVD deployment process. This ARM template utilizes both inline parameters and a `Deploy-WVD-Config.parameters.json` parameters file.

> NOTE:
>
>Ensure the `Deploy-WVD-Config.parameters.json` is updated to reflect the correct values for the Key Vault and Log Analytics references, otherwise the configuration template will not succeed.

#### **Configuration Variables**

````JSON
{
  "dscScriptName" : "[parameters('wvd_dscConfigurationScript')]",
  "dscConfigurationName": "WvdSessionHostConfig",
  "wvdResourceLocation": "[resourceGroup().location]"
}
````

- **dscScriptName**: Name of the DSC Script (should end with .ps1)
- **dscConfigurationName**: Name of the DSC Configuration
- **wvdResourceLocation**: Name of the Azure region for the resources in the deployment

#### **Configuration Resources**

- **Microsoft Monitoring Agent (Log Analytics)**:
  
  ````JSON
  {
    "apiVersion": "2019-07-01",
    "type": "Microsoft.Compute/virtualMachines/extensions",
    "name": "[concat(parameters('az_virtualMachineNames')[copyIndex()], '/MicrosoftMonitoringAgent')]",
    "location": "[variables('wvdResourceLocation')]",
    "dependsOn": [],
    "copy": {
      "name": "WVD-SH-MMA-Extension",
      "count": "[length(parameters('az_virtualMachineNames'))]"
    },
    "properties": {
      "publisher": "Microsoft.EnterpriseCloud.Monitoring",
      "type": "MicrosoftMonitoringAgent",
      "typeHandlerVersion": "1.0",
      "autoUpgradeMinorVersion": true,
      "settings": {
        "workspaceId": "[parameters('az_logAnalyticsWorkspaceId')]"
      },
      "protectedSettings": {
        "workspaceKey": "[parameters('az_logAnalyticsWorkspaceKey')]"
      }
    }
  }
  ````

- **Dependency Agent**:
  
  ````JSON
  {
    "apiVersion": "2019-07-01",
    "type": "Microsoft.Compute/virtualMachines/extensions",
    "name": "[concat(parameters('az_virtualMachineNames')[copyIndex()], '/DependencyAgent')]",
    "location": "[variables('wvdResourceLocation')]",
    "dependsOn": [
      "[resourceId('Microsoft.Compute/virtualMachines/extensions', parameters('az_virtualMachineNames')[copyIndex()], 'MMAExtenMicrosoftMonitoringAgentsion')]"
    ],      
    "copy": {
      "name": "WVD-SH-DepAgent-Extension",
      "count": "[length(parameters('az_virtualMachineNames'))]"
    },
    "properties": {
        "publisher": "Microsoft.Azure.Monitoring.DependencyAgent",
        "type": "DependencyAgentWindows",
        "typeHandlerVersion": "9.10",
        "autoUpgradeMinorVersion": true
    }
  }
  ````

- **Active Directory Domain Join**:

  ````JSON
  {
    "apiVersion": "2019-07-01",
    "type": "Microsoft.Compute/virtualMachines/extensions",
    "name": "[concat(parameters('az_virtualMachineNames')[copyIndex()], '/ActiveDirectoryDomainJoin')]",
    "location": "[variables('wvdResourceLocation')]",
    "dependsOn": [
      "[resourceId('Microsoft.Compute/virtualMachines/extensions', parameters('az_virtualMachineNames')[copyIndex()], 'DependencyAgent')]"
    ],
    "copy": {
      "name": "WVD-SH-Domain-Join-Loop",
      "count": "[length(parameters('az_virtualMachineNames'))]"
    },
    "properties": {
      "publisher": "Microsoft.Compute",
      "type": "JsonADDomainExtension",
      "typeHandlerVersion": "1.3",
      "autoUpgradeMinorVersion": true,
      "settings": {
        "name": "[parameters('dj_domainFQDN')]",
        "ouPath": "[parameters('dj_ouPath')]",
        "user": "[concat(parameters('dj_adminAccount'),'@',parameters('dj_domainFQDN'))]",
        "restart": "true",
        "options": "3"
      },
      "protectedSettings": {
        "password": "[parameters('dj_adminPassword')]"
      }
    }
  }
  ````

- **Desired State Configuration**:

  ````JSON
  {
    "apiVersion": "2019-07-01",
    "type": "Microsoft.Compute/virtualMachines/extensions",
    "name": "[concat(parameters('az_virtualMachineNames')[copyIndex()], '/Microsoft.PowerShell.DSC')]",
    "location": "[variables('wvdResourceLocation')]",
    "dependsOn": [
      "[resourceId('Microsoft.Compute/virtualMachines/extensions', parameters('az_virtualMachineNames')[copyIndex()], 'ActiveDirectoryDomainJoin')]"
    ],
    "copy": {
      "name": "WVD-SH-DSC-Config-Loop",
      "count": "[length(parameters('az_virtualMachineNames'))]"
    },
    "properties": {
      "publisher": "Microsoft.Powershell",
      "type": "DSC",
      "typeHandlerVersion": "2.80",
      "autoUpgradeMinorVersion": true,
      "settings": {
        "Configuration": {
          "url": "[parameters('wvd_sessionHostDSCModuleZipUri')]",
          "script": "[variables('dscScriptName')]",
          "function": "[variables('dscConfigurationName')]"
        },
        "configurationArguments": {
          "hostPoolName": "[parameters('wvd_hostpoolName')]",
          "registrationInfoToken": "[parameters('wvd_hostpoolToken')]",
          "wvdDscConfigZipUrl": "[parameters('wvd_dscConfigZipUrl')]",
          "deploymentFunction": "[parameters('wvd_deploymentFunction')]",
          "deploymentType": "[parameters('wvd_deploymentType')]",
          "fsLogixVhdLocation": "[parameters('wvd_fsLogixVhdLocation')]"
        }
      }
    }
  }
  ````

---

## Desired State Configuration (Session Host Customization)

There are many ways to perform a post Operating System configuration of a Session Host, however, this deployment guide is centered around using Desired State Configuration (DSC). There is a wealth of information available for DSC on the [Microsoft Docs](https://docs.microsoft.com/en-us/powershell/scripting/dsc/overview/overview?view=powershell-7) website.
