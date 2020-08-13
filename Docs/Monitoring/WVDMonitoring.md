# WVD Monitoring

Link to Github.

WVD Monitoring takes advantage of PAAS solutions such as Log analytics, Azure Monitoring and Policy.  Via policy we can ensure Diagnostic settings for all WVD components are sending their data to the correct Log Analytics workspace.  We use a function app(referenced in the Blueprints guide) for sending WVD specfic metrics to Azure Monitor.  Using these 2 platforms we can build monitoring dashboards and alerts to ensure our customers get the best experience. 

**Monitoring Components:**
* Azure Monitor
  * Log Analytics Workspace
    * Created via Azure Blueprints with all necessary solutions
      * Health
      * Service Map
      * KeyVault Analytics
      * VM Insights
      * Custom WVD Solutions
  * Alerting

## Azure Monitor
Azure Monitor maximizes the availability and performance of your applications and services by delivering a comprehensive solution for collecting, analyzing, and acting on telemetry from your cloud and on-premises environments. It helps you understand how your applications are performing and proactively identifies issues affecting them and the resources they depend on.We are able to use the platform to build Admin related dashboards that can show us all WVD infrastructure components and their respective health.  
![WVDMetricsDashboard](\pics\WVDMetricsDash.png)

If deeper analysis is needed the user can always click into the visual or the LogA icon on top right and review the data.

### Azure Log Analytics
A [workspace](https://docs.microsoft.com/en-us/azure/azure-monitor/log-query/log-query-overview) is created for each subscription that will allow for the relevant data to be kept in that subs workspace.
Via Azure policy KeyVault, Network Security Groups and WVD infrastructure components will all send their diagnostic data to their respective workspace.  From there we will use the data to build dashboards to make the data useful via Log Analytics queries.

## Azure Function App
There is a Function App created(discussed in Blueprints doc) that gathers necessary perf metrics that are reported on and used for alerting.  This FA will inject custom mentrics to Azure Monitor that are used for dashboards, alerts and automation of scaling needs.

## Alerting
[Alerts](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/alerts-overview) proactively notify you when important conditions are found in your monitoring data. They allow you to identify and address issues before the users of your system notice them.

* Navigate to the Monitoring Blade in the Azure Portal.
  ![AzureMonitorBlade](\monitorAlerts.png)
* Select Alerts -> Manage Alert Rules, once done this will take you to all alerts that are created for the selected subscriptions.(If you do not see anything ensure that the correct subscriptions have been selected at the top)
  * Notice the Target Resource Type, as these alerts can come from many differnt areas of Azure Monitor
  
![AzureAlerts](/AlertsCreated.png)
* Existing Alerts at time of documentation
  * Low Pool Capacity < 10%
  * VA Public Tunnel Connection Dropped
  * Unhealthy Host Pool Identified
  * Failure Anomalies - wvdmetrics (this is the Function App)
  * Azure Service Health Alerts

## Revision History
Date | Version | Description | Author
-----|---------|-------------|-------
05/28/2020 | 1.0 | Initial Draft | Matt Taylor
