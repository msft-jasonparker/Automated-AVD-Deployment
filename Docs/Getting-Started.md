# Getting Started

**STOP - BE SURE TO READ THROUGH [REQUIRMENTS](/Docs/Requirements.md) AND THE [POST SETUP CONFIGURATION](/Docs/Post-Setup-Configuration.md) DOCUMENTS BEFORE CONTINUING**

---

To use this repository, first clone or download to your own repository. This will allow your organization to customize the deployment code to suit your specific needs. Alternative, the repository could also be forked in the event updates to this repository need to flow to other repositories.

Open a PowerShell console and navigate to the '*Scripts*' sub-directory of the repository.  If not already done, run ```Set-ExecutionPolicy Bypass``` from an administrator console. From the '*Scripts*' sub-directory run the ```CopyToPSPath.ps1``` script which will copy the Az.WvdOperations Module into your modules directory (All Users) and then imports the module to your PowerShell session. Discover the commands in the function by typing, ```Get-Command -Module Az.WvdOperations```. If you need more information about a specific command, use ```Get-Help <cmd> -Detailed```.

Next, create the required Azure resources listed in the Requirements section. This should include not only the creation of the resources, but also the configuration of these resources. For example:

- Upload the ARM template and parameter files to the templates container in the Storage Account
- Package the DSC configuration script into an archive and upload to a Storage Account
- Upload the DSC configuration archive to the dsc container in the Storage Account
- Import or create the runbooks for Dynamic Scaling

 Update the templates and scripts based on the resources that either exist or were created to support this deployment process. The **Deployment** section will provide the step-by-step process needed to use this automated deployment repository.