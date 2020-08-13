# WVD Package Management Log File

Anytime a new applicaiton is added to the packages folder in the [WVD Packages Directory](file://vac30hsm01-6833.va.gov/vac30-wvd-netapp-pool01-vol01/wvdartifacts/Packages), this file should have a corresponding entry identifying the date of change, who made the change and what applications were added.

When this markdown file is updates and commited to the DEV branch of the repository, it will trigger a Github action to create a new 'wvd_packages.zip' file on the Azure NetApp volume.

## Package Management Log Entries

07-31-2020  -   Jason Parker    -   Added VSCode, Git, Netmon, SSMS, and Native Windows admin consoles
07-31-2020  -   Jason Parker    -   Added PowerBI Desktop