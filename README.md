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


