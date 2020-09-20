# Automated Deployment of Windows Virtual Desktop

This repo is comprised of a PowerShell module, scripts, Azure ARM templates, and ARM parameter files.  The goal of this repo is to provide any organization looking to deploy Windows Virtual Desktop, an easy to use deployment model based on a set group of standards.

## Requirements

Below are some of the minimum requirements to be able to use this repo in a Test \ Dev \ Prod environment.

---

### Knowledge

- Intermediate knowledge of PowerShell sytanx, scripts and modules (Advanced is preferred)
- Intermediate knowledge of Azure infrastructure, networking, storage and automation
- Strong understanding of ARM templates and parameters

---

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

---

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

---

## Deployment

 This section will outline the purpose / function for each of the template and parameter files along with which sections should be updated before running a deployment job. The fundamental basis for this deployment process is a series of cascading Resource Group deployments that end with the creation of the Host Pools, Application Groups, Session Hosts, and Availability Sets. The last deployment would define the configuration (Monitoring extension, Domain Join extension, and DSC extension) which ensures the Session Hosts are ready for user load.

---

### PowerShell Module Dependancies

 Before attempting to use this automated deployment process, ensure the following PowerShell modules have been installed and updated.

- Az Module (and dependancies)
- Az.DesktopVirtualization (should be installed with the Az module)
- Az.WvdOperations.psm1 (located in the Operations folder)

The Az.WvdOperations module was created to be used with this deployment process.  Located in the .\Scripts directory is a script called 'CopyToPSPath.ps1'.  Run this script to copy the module to your path and import to your session.

---

### Scale Unit ARM Template

 `.\Deployment\Deploy-WVD-ScaleUnit.json`

A "scale unit" is the term used in reference to a group of Host Pools and Session Hosts which should be deployed to meet a specific scenario. This deployment assumes the necessary planning has been done to determine the number of users per Session Host, the number of Session Hosts per Host Pool and the number of Host Pools needed for deployment.

#### **Variables**

 ```JSON
"copy": [{
  "name": "wvdAppGroupArray",
  "count": "[length(parameters('wvd_hostPoolConfig').configs)]",
  "input": "[resourceId(concat(parameters('wvd_hostPoolResourceGroupPrefix'),add(parameters('wvd_hostPoolInitialValue'),copyIndex('wvdAppGroupArray'))),'Microsoft.DesktopVirtualization/applicationgroups/',concat(parameters('az_cloudResourcePrefix'),'-wvd-hostpool-',padLeft(add(parameters('wvd_hostPoolInitialValue'),copyIndex('wvdAppGroupArray')),2,'0'),'-DAG'))]"
}],
"wvdResourceLocation": "[resourceGroup().location]",
"wvdWorkspaceName": "[concat(parameters('az_cloudResourcePrefix'),'-wvd-workspace')]",
"azDeploymentString": "[parameters('wvd_deploymentString')]"
```

- **wvdAppGroupArray**: This variable is a construct of the *to be* created Desktop Application Groups (DAG).  This is required because if you have any existing DAG(s), writing this array to the WVD workspace will override any previous DAG(s). Later in the template, we'll add this variable to the reference of the existing properties.
- **wvdWorkspaceName**: This variable uses the *az_cloudResourcePrefix* parameter to construct the WVD workspace name. Adjust this variable as needed.

#### **Resources**

The Deploy-WVD-ScaleUnit.json ARM template contains 2 resources, both of which are addition deployments. The first is the Host Pool deployment and the last is the Workspace deployment. The Host Pool deployment uses a linked template URI as the based template and the parameters are defined in line. The Workspace deployment defines the WVD Workspace resource and contains the property section below which defines the DAG(s) linked to it.

```JSON
"properties": {
  "applicationGroupReferences": "[concat(reference(resourceId(parameters('wvd_workspaceResourceGroup'),'Microsoft.DesktopVirtualization/workspaces',variables('wvdWorkspaceName')),'2019-12-10-preview','Full').properties.applicationGroupReferences,variables('wvdAppGroupArray'))]"
}
```

As you can see from the code above, the *applicationGroupReferences* is a combination of the existing references along with the variable above.

#### **Outputs**

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
  - sessionHostNames

---

### Scale Unit Parameter File

`.\Deployment\Deploy-WVD-ScaleUnit.parameters.json`

The parameter file is the main engine which drives the deployment of the "scale unit".  Each of the parameters in the file have metadata descriptions to aide in understand each of the parameters intended purpose.  Below is the detail information for the *wvd_hostPoolConfig* parameter, which is an object.

```JSON
"wvd_hostPoolConfig": {
  "value": {
    "configs": [
      {
        "deploymentType": "<deployment-type>",
        "deploymentFunction": "<deployment-function>",
        "fsLogixVhdLocation": "\\\\servername\\sharename",
        "dscConfiguration": "DscConfiguration.ps1.zip",
        "azVmNumberOfInstances": 20
      },
      {
        "deploymentType": "<deployment-type>",
        "deploymentFunction": "<deployment-function>",
        "fsLogixVhdLocation": "\\\\servername\\sharename",
        "dscConfiguration": "DscConfiguration.ps1.zip",
        "azVmNumberOfInstances": 20
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

#### **Functions**

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

#### **Variables**

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

#### **Resources**

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
        // if the group reference count is greater than 3, use 3 fault domains, else use the group reference count as the number of fault domains
        "platformFaultDomainCount": "[if(greater(length(parameters('wvd_groupReference')),3),3,length(parameters('wvd_groupReference')))]",
        // update domain max count is 20, if less than 20 use session host instance count as update domain count
        "platformUpdateDomainCount": "[if(greater(variables('wvdSessionHostInstances'),20),20,variables('wvdSessionHostInstances'))]"
    },
    "sku": {
        "name": "Aligned"
    } 
  }
  ````

- **Session Host Deployment Job**:

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
          //Truncated; see actual ARM template
        }
    }
  }
  ````

