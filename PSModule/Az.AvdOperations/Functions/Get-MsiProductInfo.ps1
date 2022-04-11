Function Get-MsiProductInfo {
    [CmdletBinding()]
    Param (
        [System.String]$msiPath
    )

    # Definition
    $sig = @'
    [DllImport("msi.dll", CharSet = CharSet.Unicode, PreserveSig = true, SetLastError = true, ExactSpelling = true)]
    private static extern UInt32 MsiOpenPackageW(string szPackagePath, out IntPtr hProduct);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, PreserveSig = true, SetLastError = true, ExactSpelling = true)]
    private static extern uint MsiCloseHandle(IntPtr hAny);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, PreserveSig = true, SetLastError = true, ExactSpelling = true)]
    private static extern uint MsiGetPropertyW(IntPtr hAny, string name, StringBuilder buffer, ref int bufferLength);
    private static string GetPackageProperty(string msi, string property)
    {
        IntPtr MsiHandle = IntPtr.Zero;
        try
        {
            var res = MsiOpenPackageW(msi, out MsiHandle);
            if (res != 0)
            {
                return null;
            }
            int length = 256;
            var buffer = new StringBuilder(length);
            res = MsiGetPropertyW(MsiHandle, property, buffer, ref length);
            return buffer.ToString();
        }
        finally
        {
            if (MsiHandle != IntPtr.Zero)
            {
                MsiCloseHandle(MsiHandle);
            }
        }
    }
    public static string GetProductCode(string msi)
    {
        return GetPackageProperty(msi, "ProductCode");
    }
    public static string GetProductName(string msi)
    {
        return GetPackageProperty(msi, "ProductName");
    }
'@
    $msiTools = Add-Type -PassThru -Namespace 'Microsoft.Windows.DesiredStateConfiguration.PackageResource' -Name 'MsiTools' -Using 'System.Text' -MemberDefinition $sig


    # Get the MSI Product Name
    $msiProductName = $msiTools::GetProductName($msiPath)
    # Get the MSI Product ID / GUID
    $msiProductGuid = $msiTools::GetProductCode($msiPath)

    $output = [PSCustomObject][Ordered]@{
        ProductName = $msiProductName
        ProductGuid = $msiProductGuid
    }

    Return $output
}