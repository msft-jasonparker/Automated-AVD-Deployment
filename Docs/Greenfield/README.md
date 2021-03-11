# Greenfield Deployments

Greenfield deployments are great for those who are looking to understand how to use the Automated WVD Deployment solution.

> **WARNING:**
> 
> The foundation deployment assumes you have a functioning Active Directory in or connected to your Azure subscription

---

## Architecture Example (my personal lab)

![WVD-Architecture](/Docs/_media/WVD-Architecture.png)

---

## Deploy Azure Foundation

The Azure foundation setup will create all the necessary Azure components that are required to use the deployment solution.

**Azure Public** | **Azure Government**
--- | ---
[![Deploy To Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fmsft-jasonparker%2FAutomated-WVD-Deployment%2Fdev-test%2FSetup%2FDeploy-WVD-Foundation.json) | [![Deploy To Azure US Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fmsft-jasonparker%2FAutomated-WVD-Deployment%2Fdev-test%2FSetup%2FDeploy-WVD-Foundation.json)

### Required Parameters and Default Values

When deploying to the Azure Portal, you can change the default values. Be sure you remember the changes you make if you deviate from the defaults.

```JSON
    "parameters": {
        "KeyVaultAccessObjectId": {
            "type": "string",
            "defaultValue": "00000000-0000-0000-0000-000000000000",
            "metadata": {
                "description": "NOTE: Provide the ObjectId of the Azure AD user or group that will be given access to the Key Vault secrets"
            }
        },
        "KeyVaultSecretVMDomainJoinAccount": {
            "type": "string",
            "defaultValue": "admin@consoto.com",
            "metadata": {
                "description": "NOTE: This should be an account with domain join rights in your AD domain"
            }
        },
        "KeyVaultSecretVMDomainJoinPassword": {
            "type": "securestring",
            "defaultValue": "S3crEtP@$$w0r|>",
            "metadata": {
                "description": "NOTE: Provide the password for the domain join account"
            }
        },
        "KeyVaultSecretVMDomainJoinOU": {
            "type": "string",
            "defaultValue": "CN=Computers,DC=constoso,dc=com",
            "metadata": {
                "description": "NOTE: Organizational Unit where Session Host computer accounts are created"
            }
        },
        "KeyVaultSecretVMLocalAdminAccount": {
            "type": "string",
            "defaultValue": "laa_administrator",
            "metadata": {
                "description": "NOTE: Provide the name for the local vm administrator account"
            }
        },        
        "KeyVaultSecretVMLocalAdminPassword": {
            "type": "securestring",
            "defaultValue": "S3crEtP@$$w0r|>",
            "metadata": {
                "description": "NOTE: Provide the password for the local vm administrator account"
            }
        },
        "HostPoolResourceGroupPrefix": {
            "type": "string",
            "defaultValue": "WVD-POOL-RG-",
            "metadata": {
                "description": "NOTE: This solution assumes Host Pools will be contained in their own Resource Groups"
            }
        },
        "ServicesResourceGroupName": {
            "type": "string",
            "defaultValue": "WVD-SVCS-RG",
            "metadata": {
                "description": "NOTE: The Services Resource Group is created for non-WVD resources"
            }
        },
        "NetworkResourceGroupName": {
            "type": "string",
            "defaultValue": "WVD-NET-RG",
            "metadata": {
                "description": "NOTE: The Network Resource Group is created for all network resources"
            }
        },
        "StorageAccountName": {
            "type": "string",
            "defaultValue": "wvdartifactblobstore",
            "metadata": {
                "description": "NOTE: This storage account will contain blob containers for DSC configuration, ARM templates, and file shares for WVD profiles"
            }
        },
        "KeyVaultNamePrefix": {
            "type": "string",
            "defaultValue": "WVD-KV",
            "metadata": {
                "description": "NOTE: The full name for the Key Vault resource will include a unique string appended to the end"
            }
        },
        "AutomationAccountNamePrefix": {
            "type": "string",
            "defaultValue": "WVD-AA",
            "metadata": {
                "description": "NOTE: The full name for the Automation Account resource will include a unique string appended to the end"
            }
        },
        "LogAnalyticsWorkspaceNamePrefix": {
            "type": "string",
            "defaultValue": "WVD-LA",
            "metadata": {
                "description": "NOTE: The full name for the Log Analytics resource will include a unique string appended to the end"
            }
        },
        "VirtualNetworkName": {
            "type": "string",
            "defaultValue": "WVD-VNET",
            "metadata": {
                "description": "NOTE: This solution only creates a single Virtual Network, update the AddressSpace parameter to use an alternate address"
            }
        },
        "VirtualNetworkAddressSpace": {
            "type": "string",
            "defaultValue": "172.20.0.0/16",
            "metadata": {
                "description": "NOTE: Class B Network Address Space, update to any private IP address space"
            }
        },
        "VirtualNetworkDNSServer": {
            "type": "string",
            "defaultValue": "AzureDNS",
            "metadata": {
                "description": "NOTE: Enter the IP Address of the DNS Server to be used in the WVD-VNET or use AzureDNS"
            }
        },
        "VirtualNetworkSubnetAddress": {
            "type": "string",
            "defaultValue": "172.20.0.0/24",
            "metadata": {
                "description": "NOTE: Class C Subnet address space, update to any private IP address space"
            }
        },
        "VirtualNetworkSubnetCount": {
            "type": "int",
            "defaultValue": 2,
            "metadata": {
                "description": "NOTE: Number of subnets to create, be sure that the VNET and Subnets fit correctly. Additional subnets will be incremented numerically."
            }
        },
        "VirtualNetworkSubnetPrefix": {
            "type": "string",
            "defaultValue": "WVD-Subnet-",
            "metadata": {
                "description": "NOTE: Each Subnet will have this prefix and have an incremented 2-digit numeric value assigned (i.e. 01, 02, 03, etc.)"
            }
        },
        "HostPoolResourceGroupsToCreate": {
            "type": "int",
            "defaultValue": 2,
            "metadata": {
                "description": "NOTE: This numeric value specifies the number of Resource Groups to create based on the number of Host Pool you plan to deploy"
            }
        }
    }
```

[**Back --->>> Table of Contents**](../../README.md)

[**Next --->>> Post Setup Configuration**](Post-Setup-Configuration.md)