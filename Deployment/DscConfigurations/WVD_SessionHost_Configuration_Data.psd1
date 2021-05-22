@{
    AllNodes = @(
        @{
            NodeName = "*"
            DscSourcePath = "C:\ProgramData\WVD-Automated-Deployment"
        }
    );
    WvdData = @{
        WvdAgentInstallUri = $null
    }
}