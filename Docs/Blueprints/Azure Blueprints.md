# Azure Blueprints
[Azure Bluprints](https://docs.microsoft.com/en-us/azure/governance/blueprints/overview) are exported as a JSON template and stored on VA's Commercial GitHub.

Link to Github.

## What steps happen to make it ready?
Azure Blueprints provides a template for creating the required infrastructure to support the VA's Windows Virtual Desktop in a new subscription. This automated approach will programmatically create and configure the subscription. This can be done via the Azure portal or Powershell.

**Blueprints:**
* CreateWVDRGs
    * 16 Resource Groups for WVD HostPools and respective Session Hosts.
    * 1 Mgmt. Resource Group which contains:
        * Log Analtyics Workspace
        * Storage Account
        * KeyVault
* NIST 800-53
* VNETandSubs
    * Networking Resource Group
    * VNET
    * Subnets
    * Default Route Table

## Azure Automation Runbooks
There is a Core Automation Account that will do the core work such as updating Route Tables, scaling up and down the WVD infrastructure and more.
### Components:
* Automation Account
  * wvd-core-int-east-automation
     * AAD Service Principal as RunAs
     * Contributor at WVD-All Management Level
* Runbooks can be imported from GitHub
  * Update_Route_Tables
  * Scaling of WVD infrastructure
  * Any more needed.    

## Azure Function App
There is a Function App created that gathers necessary perf metrics that are reported on and used for alerting.  This will inject custom mentrics to Azure Monitor.
### Components:
* Function App
    * Name: wvdmetrics
    * Interval: 5 mins    

## Steps to Create New subscription 
> (At this time the subscription must be manually created)
> 
* A Cloud account is already created in commercial AAD (**sub-owner@dvagov.onmicrosoft.com**)
* Account is disabled and must be enabled with new credentials generated (Harvey Hayes owns this process)
* Authenticate to the [EA Portal](https://ea.azure.com) using cloud account
* Create new subscription and this will take you to the Azure portal once complete.
* Find your newly created subscription and rename to match naming scheme. 
  	* EX: _WVD-Public-External-xx_
* Once completed, contact Harvey Hayes to let him know work completed and to disable account

### Portal
  * Login to the Azure Portal, navigate to Management Groups(You must have appropriate permissions to see and manage for the following steps).
  ![MGimage](/WVD/Pictures/MGPortal.png)
  * Search for the new subscription (can take 15-30 minutes post rename action).  
    * Click the elipsis to the right of the Subscription Name / ID.  
    * Select MOVE -> In the "New Parent Management Group" dropdown, select WVD-All (WVD_All).  

### Blueprints
* While in the Azure Portal, navigate to Blueprints. 
![BlueprintPortal.png](/WVD/Pictures/BlueprintsPortal.png)

* Under the "Welcome to Azure Blueprints" header, Select Apply under "Apply to a scope".
* This screen shows a list of available blueprints.  
  * Start with networking, Select blueprint **VNETandSubs**
  * Once selected, please click on "Assign blueprint"
  * Select the new subscription from the Subscriptions dropdown under "Assignment name"
  * Rename the Assignment-VNETandSubs to region-VNETandSubs. 
      * EX: _WESTUS-VNETandSubs_
  * Select location to be deployed to.  
  * For "Lock Assignment" select "Don’t Lock".  
  * Under Managed Identity, select User Assigned and click the elipsis.  
      * Select WVD_BlueprintAdmin and click "Add"
  * Under Artifact parameters, fill in the required values.  These should be supplied from networking resources as they have already carved out the needed network for each region.
  * Once artifact parameters are completed, click "Assign"
* Once the assignment has completed, continue with **CreateWVDRGs**
  * Follow the steps above required for the blueprint.  
      * You will need to fill out the "Resource Group Name" field, using standard nameing conventions. 
         * EX: _WVD-PROD-MAP-WESTUS-SVCS-RG_
      * Select the matching Resource Group Location from the dropdown.  Below that you will see default values for AdminServices.  
          * Leave these default.
      * You will need to enter the following for objectID: _045a2650-2841-46dc-a2bc-5fd74a97c6fc_
          * Note: This is the object ID for the _VAOITWINDOWVIRTUALDESKTOP_ AD group.
      * Click "Assign" at the bottom.
* Once the assignment has completed, you will see the list of resources that were created.  
  * Scroll down and click on the log analytics workspace that was created.
      * Click on Properties (under General), highlight and copy the Resource ID to your clipboard.  You will need this Resource ID before you complete the NIST blueprint.
* Back to the Blueprint dashboard, select **NIST** and click Assign.
  * Follow the steps above required for the blueprint and fill out the required fields at the top and scroll down to artifact parameters.
  * Under Subscription, [Preview] Log Analytics workspace ID - paste the value into the field to the right.  This is the log analytics workspace that was created as part of the **CreateWVDRGs** blueprint.  This workspace ID will need to be pasted into multiple artifact values (each artifact that references "Log Analytics workspace".

## Policy
* Under the Policy blade in the Azure Portal, click on Defintions under Authoring.
![Policyimage](/WVD/Pictures/PolicyPortal.png)

* Once selected, click on the initiative named _VA - Diag and LogA Agent_ and select "Assign" at the top of the page.  
* Once the Assingment opens click the elipsis after Scope and select the correct subscription and click "Accept" at the bottom.
    * Under Assignment name field, rename VA - Diag and LogA Agent to something that matches your subscription ID
        * EX: _[02] - Diag and LogA Agent_ for subscription WVD-XX-02.
    * Click Next.
    * Under Log Analytics Workspace, click the elipsis.
        * Under Subscription, click the drop down and select the correct subscription.
        * Under workspaces select the dropdown and select the previously created Log Analytics workspace.  
        * Click Select at the bottom and click next.  
    * On the remediation screen, check the box for "Create a remediation task" and ensure your managed identity is in the correct location dropdown box.  
    * Click Review + create" at the bottom.

## Security Center
* Under the Security Center Blade select Pricing & settings.  
![SecurityCenterimage](/WVD/Pictures/SecurityCenterPortal.png)

* Select the newly created subscription from the list.
![SecurityCenterPSimage](/WVD/Pictures/SecurityCenterPandS.png)

  * On Pricing Tier - ensure "Standard" is selected and click Save. 
  * On Data Collection - ensure "Auto Provisioning" is ON and your Workspace configuration is using the newly created Log Analytics workspace from the dropdown.
  * Click "Save" at the top of the page.
* Return to the top level of Pricing and settings and select your new Log Analytics workspace.
  * On Pricing Tier - ensure "Standard" is selected and click Save. 
  * On Data Collection - select Common and click Save.

## Revision History
Date | Version | Description | Author
-----|---------|-------------|-------
05/28/2020 | 1.0 | Initial Draft | Matt Taylor
