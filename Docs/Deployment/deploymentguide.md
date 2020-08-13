# Windows Virtual Desktop (WVD) Deployment Guide

> Note:  These instructions assume a minimal deployment of a **SINGLE** scale unit as defined by the WVD infrastructure documents, found [here](../Infrastructure/wvd_infrastructure.md#host-pool).

## Dependencies

- **Permissions**
  - Minimum required permssions to deploy WVD is '**Contributor**' role over the subscriptions for each deployment
- **Tools / Software**
  - PowerShell Modules
    - Az (includes all sub-modules)
    - Az.DesktopVirtualization
    - Az.NetAppFiles
  - Git
    - Requires cloning the [repository](https://github.com/department-of-veterans-affairs/windows-virtual-desktop.git) to the computer running the deployment
  - Visual Studio Code (*optional*)
- **Azure Resources**
  - The [WVD Blueprints](../Blueprints/AzureBlueprints.md) document outlines what is created to support WVD
- **Azure Networking**
  - `Jeff Arthur`
- **Identity Services**
  - `Sean Mullin`

## Deploy Azure NetApp Files (ANF) Resources

> Note: Only run the following deployment in an Azure region where there are not any ANF resources.  Once deployed, changes to the capacity pool and volume sizes must be done through the Azure portal.  In addition, if *new* capactiy pools or volumes are needed, those also need to be created in the Azure portal.

1. Review the [Deploy-ANF-Volume.parameters.json](https://github.com/department-of-veterans-affairs/windows-virtual-desktop/blob/master/ARM/ANF/Deploy-ANF-Volume-Template.parameters.json) file and update the following  parameters to reflect the environment where these resources will be deployed.

    ```JSON
    "va_cloudResourcePrefix": {
        "value": ""
    },
    "va_adSiteName": {
        "value": ""
    },
    "vn_virtualNetworkName": {
        "value": ""
    },
    "vn_virtualNetworkResourceGroupName": {
        "value": ""
    },
    "anf_netappAccountName": {
        "value": ""
    },
    "anf_netappCapacityPoolName": {
        "value": ""
    },
    "anf_netAppVolumeCount": {
        "value": 
    },
    "anf_netappVolumeName": {
        "value": ""
    },
    "anf_delegatedSubnetName": {
        "value": ""
    }
    ```

2. Open PowerShell
    - Connect to Azure

        ```PowerShell
        Connect-AzAccount -Environment AzureCloud
        ```

        - Enter your e-mail address

            ![img](../_Media/azure-portal-login-1.png)

        - Select the option for X.509 certificates

            ![img](../_Media/azure-portal-login-2.png)

        - Select the correct certificate which as the correct permissions over the subscription, click `OK `, and enter your PIN

            ![img](../_Media/azure-portal-login-3.png)

    - Navigate to the directory where the [repository](https://github.com/department-of-veterans-affairs/windows-virtual-desktop.git) was cloned
    - Deploy the ANF resources
        > Note: This operation make take some time

        ```PowerShell
        New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName -TemplateFile $pathToTemplateFile -TemplateParameterFile $pathToParameterFile
        ```

3. Open an Internet Browser (Edge or Chrome)
    - Go to [https://portal.azure.com](https://portal.azure.com)
    - From the search bar in the Azure portal, type `NetApp` and select `Azure NetApp Files` from the list of services

        ![img](../_Media/anf-1.png)

    - Select the ANF Account

        ![img](../_Media/anf-2.png)

    - Click on 'Volumes'

        ![img](../_Media/anf-3.png)

    - Locate the name of the ANF Volume(s) created and make **note** of the mount path as this will be required during the WVD deployment

        ![img](../_Media/anf-4.png)

## Deploy WVD Resources

> Note: If this is a `redeployment`, the WVD Workspace, Host Pool, and App Group resources may still exist and the redeployment will only create new Session Hosts.

### Create Shared Access Signature (SAS) tokens for Azure Resource Manager (ARM) templates

1. Open an Internet Browsers (Edge or Chrome)
    - Navigate to [https://portal.azure.com](https://portal.azure.com)
    - From the search bar in the Azure portal, `type` and `select` the name of the region specific storage account (e.g. vac30artifactblobstore)

        ![img](../_Media/sas-token-1.png)

    - Select `Containers` from the main window for the Storage Account

        ![img](../_Media/sas-token-2.png)

    - Select the `templates` container

        ![img](../_Media/sas-token-3.png)

    - Below are the files that need SAS token(s) and URL(s)

        - ARM templates in the `templates\WindowsVirtualDesktop\` folder
            
            ![img](../_Media/sas-token-4b.png)
        
        - DSC ZIP file in the `dsc` container

            ![img](../_Media/sas-token-4a.png)  

    - Select the `...` (3 elipses) on the far right side of the rows, then select `Generate SAS`

        ![img](../_Media/sas-token-5.png)

    - Set the expration time to xx days into the future, click `Generate SAS token and URL` then copy and save the `Blob SAS URL`
        > Note: Do this for each files shown above template in the folder

        ![img](../_Media/sas-token-6.png)


## Setup and Create WVD Deployment(s)

1. Review the [Deploy-WVD-ScaleUnit.parameters.json](../../ARM/Deploy-WVD-ScaleUnit.parameters.json) file and update the following parameters to reflect the environment and scale unit to be deployed.

    ```JSON
    {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "az_vmNumberOfInstances": {
                "value": 65,
                "metadata": {
                    "description": "The number of Session Host VM(s) to deploy in each Host Pool."
                }
            },
            "az_vmSize": {
                "value": "Standard_D8s_v3",
                "metadata": {
                    "description": "Size of the Session Host VM to deploy.  This should correspond to the wvd_maxSessionLimit parameter to align to the 1 user session per CPU core model."
                }
            },
            "az_vmImageOffer": {
                "value": "windows-10",
                "metadata": {
                    "description": "[DO NOT CHANGE] Azure VM Image Offer without the built-in Office product."
                }
            },
            "az_vmImagePublisher": {
                "value": "MicrosoftWindowsDesktop",
                "metadata": {
                    "description": "[DO NOT CHANGE] Azure VM Image Publisher for multi-session Windows 10."
                }
            },
            "az_vmImageSKU": {
                "value": "19h2-evd",
                "metadata": {
                    "description": "[DO NOT CHANGE] Azure VM Image SKU for Windows 10 1909."
                }
            },
            "az_vmDiskType": {
                "value": "Premium_LRS",
                "metadata": {
                    "description": "[DO NOT CHANGE] Azure VM OS Disk Type."
                }
            },
            "va_cloudResourcePrefix": {
                "value": "vac30",
                "metadata": {
                    "description": "Update this value to reflect the VA region prefix for cloud resources."
                }
            },
            "va_wkstaPrefix": {
                "value": "c30",
                "metadata": {
                    "description": "Update this value to reflect the VA region prefix for domain joined computers."
                }
            },
            "vn_virtualNetworkName": {
                "value": "WVD-MAP-PROD-EASTUS",
                "metadata": {
                    "description": "Update this value to reflect the Virtual Network name based on the deployment region."
                }
            },
            "vn_virtualNetworkSubnetPrefix": {
                "value": "N2-Subnet-",
                "metadata": {
                    "description": "Update this value to reflect the subnet naming prefix in the deployment region. This value is used in a 'copy' loop and the names are derived from the 'copy count'."
                }
            },
            "vn_virtualNetworkResourceGroupName": {
                "value": "WVD-PROD-MAP-EASTUS-NETWORK-RG",
                "metadata": {
                    "description": "Update this value to reflect the location of the 'vn_virtualNetworkName' parameter"
                }
            },
            "wvd_hostPoolTemplateUri": {
                "value": "https://vac30artifactblobstore.blob.core.windows.net/templates/WindowsVirtualDesktop/Deploy-WVD-HostPool.json?sp=r&st=2020-05-06T03:14:22Z&se=2020-06-30T11:14:22Z&spr=https&sv=2019-10-10&sr=b&sig=t7Cn2dGjmbfBooGUskLmQAaiang8naiC54zNmwFLarI%3D",
                "metadata": {
                    "description": "Update this value to reflect the newly created URL(s) from the deployment guid.  This URL is for the 'Deploy-WVD-HostPool.json' file."
                }
            },
            "wvd_sessionHostTemplateUri": {
                "value": "https://vac30artifactblobstore.blob.core.windows.net/templates/WindowsVirtualDesktop/Deploy-WVD-SessionHosts.json?sp=r&st=2020-05-06T03:15:00Z&se=2020-06-30T11:15:00Z&spr=https&sv=2019-10-10&sr=b&sig=M5VlBsQg2%2FBi7Xx4hrYfvfrf3O7dqj2R%2BpV8xtq70FU%3D",
                "metadata": {
                    "description": "Update this value to reflect the newly created URL(s) from the deployment guid.  This URL is for the 'Deploy-WVD-SessionHosts.json' file."
                }
            },
            "wvd_sessionHostDSCTemplateUri": {
                "value": "https://vac30artifactblobstore.blob.core.windows.net/templates/WindowsVirtualDesktop/WvdWin10Config.json?sp=r&st=2020-05-08T16:42:45Z&se=2020-07-01T00:42:45Z&spr=https&sv=2019-10-10&sr=b&sig=CuCUZvoan5bW4%2BNg0n25Sn5MrfkpzAkDej%2FEVwlL%2FOw%3D",
                "metadata": {
                    "description": "Update this value to reflect the newly created URL(s) from the deployment guid.  This URL is for the 'WvdWin10Config.json' file."
                }
            },
            "wvd_sessionHostDSCModuleZipUri": {
                "value": "https://vac30artifactblobstore.blob.core.windows.net/dsc/WvdWin10Config.zip?sp=r&st=2020-04-22T19:35:38Z&se=2020-06-01T03:35:38Z&spr=https&sv=2019-02-02&sr=b&sig=6s0XA2PYdzIl23%2FfU%2Fxze1oIox1WF1EdDyEOS%2F5XhtI%3D",
                "metadata": {
                    "description": "Update this value to reflect the newly created URL(s) from the deployment guid.  This URL is for the 'WvdWin10Config.zip' file."
                }
            },
            "wvd_keyVaultId": {
                "value": "/subscriptions/f5d65f77-695f-42ba-a165-6764208c53c1/resourceGroups/WVD-CORE-MAP-EASTUS-SVCS-RG/providers/Microsoft.KeyVault/vaults/wvd-core-eastus-kv",
                "metadata": {
                    "description": "Update this value to reflect the resource id of the KeyVault where the secrets are store for the deployment region."
                }
            },
            "wvd_workspaceName": {
                "value": "vac30-wvd-workspace",
                "metadata": {
                    "description": "Update this value to reflect the WVD workspace name in the deployment region."
                }
            },
            "wvd_workspaceResourceGroup": {
                "value": "WVD-PROD-MAP-EASTUS-SVCS-RG",
                "metadata": {
                    "description": "Update this value to reflect the Resource Group where the 'wvd_workspaceName' parameter was created."
                }
            },
            "wvd_hostPoolResourceGroupPrefix": {
                "value": "WVD-PROD-MAP-EASTUS-POOL-RG-",
                "metadata": {
                    "description": "Update this value to reflect the Resource Group naming prefix based on the deployment region.  This value is used in a 'copy' loop and the names are derived from the 'copy count'."
                }
            },
            "wvd_maxSessionLimit": {
                "value": 8,
                "metadata": {
                    "description": "Update this value to reflect the maximum session limit per Session Host. Should be based on 1 user session per CPU core of the VM size."
                }
            },
            "wvd_loadBalancerType": {
                "value": "BreadthFirst",
                "metadata": {
                    "description": "Update this value to reflect how the user session are distributed across the Host Pool. BreadthFirst = Spread OUT across Session Hosts | DepthFirst = Spread DOWN into each Session Host."
                }
            },
            "wvd_customRdpProperty": {
                "value": "audiomode:i:0;audiocapturemode:i:1;encode redirected video capture:i:1;redirected video capture encoding quality:i:1;camerastoredirect:s:*;drivestoredirect:s:;redirectclipboard:i:0;redirectprinters:i:0;use multimon:i:0;singlemoninwindowedmode:i:1;maximizetocurrentdisplays:i:1;screen mode id:i:2;smart sizing:i:0;dynamic resolution:i:1;authentication level:i:0;gatewaycredentialssource:i:0;Kdcproxyname:s:kproxy.federation.va.gov",
                "metadata": {
                    "description": "Update this value to reflect the RDP settings that ultimately get pushed to the Windows Desktop client application and determine the default connection parameters for WVD."
                }
            },
            "wvd_apiVersion": {
                "value": "2019-12-10-preview",
                "metadata": {
                    "description": "Update this value to reflect the API version for the WVD resource objects."
                }
            },
            "wvd_hostPoolInitialValue": {
                "value": 1,
                "metadata": {
                    "description": "Update this value to reflect the starting number of the Host Pool to deploy. This number should correspond to the 'wvd_hostPoolResourceGroupPrefix' parameter as these are precreated in each region."
                }
            },
            "wvd_hostPoolConfig": {
                "value": {
                    "configs": [
                        {
                            "deploymentType": "BYOD",
                            "fsLogixLocation": "\\\\vac30hsm01-6833.va.gov\\vac30-wvd-netapp-pool01-vol01"
                        },
                        {
                            "deploymentType": "GFE",
                            "fsLogixLocation": "\\\\vac30hsm01-6833.va.gov\\vac30-wvd-netapp-pool01-vol01"
                        }
                    ]
                },
                "metadata": {
                    "description": "Update this value to reflect the number of Host Pools to create, the type Host Pool it will serve and the location of the FSLogix profiles."
                }
            },
            "ouPath": {
                "value": "OU=VDI Azure Hosts,OU=Azure,OU=VAEC,DC=VA,DC=GOV",
                "metadata": {
                    "description": "[DO NOT CHANGE] Organizational Unit where WVD computer accounts are created."
                }
            },
            "domain": {
                "value": "va.gov",
                "metadata": {
                    "description": "[DO NOT CHANGE] Domain name to join for the Session Hosts."
                }
            }
        }
    }
    ```

2. After updating the parameters, `Save` the file.

3. Open PowerShell
    - Connect to Azure

        ```PowerShell
        Connect-AzAccount -Environment AzureCloud
        ```

        - Enter your e-mail address

            ![img](../_Media/azure-portal-login-1.png)

        - Select the option for X.509 certificates

            ![img](../_Media/azure-portal-login-2.png)

        - Select the correct certificate which as the correct permissions over the subscription, click `OK `, and enter your PIN

            ![img](../_Media/azure-portal-login-3.png)

    - Navigate to the directory where the [repository](https://github.com/department-of-veterans-affairs/windows-virtual-desktop.git) was cloned
    
    - Create a new Resource Group Deployment for WVD
        > Note: This operation make take some time depending on the number of resources to create.

        ```PowerShell
        New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName -TemplateFile $pathToTemplateFile -TemplateParameterFile $pathToParameterFile
        ```

## WVD Deployment Process

The WVD deployment is comprised of four JSON ARM templates and two DSC configuration ZIP files.  Currently, all these files are stored in a centralized storage account in the SVCS based resource group for the region (e.g. WVD-PROD-MAP-EASTUS-SVCS-RG), with the exception of the [Deploy-WVD-ScaleUnit.json](https://github.com/department-of-veterans-affairs/windows-virtual-desktop/blob/master/ARM/Deploy-WVD-ScaleUnit.json) template.

> **Example PowerShell command syntax**
>
>`New-AzResourceGroupDeployment -ResourceGroupName WVD-PROD-MAP-EASTUS-SVCS-RG' -TemplateFile .\Deploy-WVD-ScaleUnit.json -TemplateParameterFile Deploy-WVD-ScaleUnit.parameters.json`

The [Deploy-WVD-ScaleUnit.json](https://github.com/department-of-veterans-affairs/windows-virtual-desktop/blob/master/ARM/Deploy-WVD-ScaleUnit.json) template along with the [Deploy-WVD-ScaleUnit.parameters.json](https://github.com/department-of-veterans-affairs/windows-virtual-desktop/blob/master/ARM/Deploy-WVD-ScaleUnit.pararmeters.json) parameters file are the files which deploys the WVD scale unit.  The parameters file contains all of the settings needed for the deployment to run.  Below is a sample outline of how this deployment would be executed:

> Note: The resources and deployments have interdependencies which need to be understood and accounted for when reviewing these templates

1. Based on the parameter file values, the template creates an Azure resource group deployment for the WVD host pools.
    - **Deployment Name:**  Deploy-WVD-HostPool-xx (xx is the WVD host pool numerical differentiator)
    - **Linked Template URI:**  https://vac30artifactblobstore.blob.core.windows.net/templates/WindowsVirtualDesktop/Deploy-WVD-HostPool.json + `SAS token`
2. The host pool deployment creates the following resources:
    - WVD host pool (e.g. vac30-wvd-hostpool-01)
    - WVD app group (e.g. vac30-wvd-hostpool-01-DAG)
    - WVD session host resource group deployment
        - **Deployment Name:** Deploy-WVD-SessionHosts
        - **Linked Template URI:** https://vac30artifactblobstore.blob.core.windows.net/templates/WindowsVirtualDesktop/Deploy-WVD-SessionHosts.json + `SAS token`
3. The session host deployment creates the following resources:
    - Virtual network interface
    - Virtual machine
    - Azure extension - MMAextension
    - Azure extension - joinDomain
    - Azure extension - dscextension (WVD DSC)
    - VA DSC resource group deployment
        - **Deployment Name:**  `session host name-` + DSCLinkedTemplate
        - **Linked Template URI:** https://vac30artifactblobstore.blob.core.windows.net/templates/WindowsVirtualDesktop/WvdWin10Config.json + `SAS token`
4. The DSC resource group deployment creates another dscextension resource which is used to configure the Windows 10 operation system to the VA standards prior to enabling the session host for use.
5. After all the above resources have been deployed, the WVD workspace is updated with the newly created app groups.

> Note: The deployment process above does not account for how users are granted access to WVD.  The app groups can contain user **OR** group assignments and should reflect VA policies and procedures before granting access.
