# Automated Deployment of Windows Virtual Desktop

This repo is comprised of a PowerShell module, scripts, Azure ARM templates, and ARM parameter files.  The goal of this repo is to provide any organization looking to deploy Windows Virtual Desktop, an easy to use deployment model based on a set group of standards.

## Requirements

Below are some of the minimum requirements to be able to use this repo in a Test \ Dev \ Prod environment.

### Knowledge

- Intermediate knowledge of PowerShell sytanx, scripts and modules (Advanced is preferred)
- Intermediate knowledge of Azure infrastructure, networking, storage and automation
- Strong understanding of ARM templates and parameters

### Azure

- At least 1 Azure Subscription - depending on the size of your organization, you may want to have multiple subscriptions based on regions (Core sub, EastUS sub, WestUS sub, EMEA sub)
- Resource naming convention suitable for interitive processes
  - Resource Groups
    - WVD-RG-01
    - WVD-RG-02
