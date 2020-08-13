# Script to import required VA certificates and install the WVD client for BYOD

# Download and import VA certificates
#Write-Host `t"Adding VA certificates to local machine" -BackgroundColor Blue

# Root certificate
try{
    $rootCertDownloadURI = "http://aia.pki.va.gov/pki/aia/va/VA-Internal-S2-RCA1-v1.cer"
    $rootCertOutFile = "$env:USERPROFILE\Downloads\VA-Internal-S2-RCA1-v1.cer"
    Invoke-WebRequest -Uri $rootCertDownloadURI -OutFile $rootCertOutFile
    certutil -addstore -user -f "Root" $rootCertOutFile | Out-Null
}catch{
    Write-Host `t"Error importing VA root certificate" -ForegroundColor Red
}

# Intermediate certificate
try{
    $intermediateCertDownloadURI = "http://aia.pki.va.gov/pki/aia/va/VA-Internal-S2-ICA1-v1.cer"
    $intermediateCertOutFile = "$env:USERPROFILE\Downloads\VA-Internal-S2-ICA1-v1.cer"
    Invoke-WebRequest -Uri $intermediateCertDownloadURI -OutFile $intermediateCertOutFile
    certutil -addstore -user -f "CA" "$env:USERPROFILE\Downloads\VA-Internal-S2-ICA1-v1.cer" | Out-Null
}catch{
    Write-Host `t"Error importing VA intermediate certificate" -ForegroundColor Red
}

# Detect OS architecture (32, 64, or ARM64)
#Write-Host `t"Detecting Operating System Architecture" -BackgroundColor Blue
try{
    $OSArchitecture = (Get-WmiObject win32_operatingsystem).OSArchitecture
}catch{
    Write-Host `t"OS Architecture not found" -ForegroundColor Red
}

# Depending on OS architecture, set proper download URI
if($OSArchitecture -eq "64-bit"){
    $wvdDownloadURI = "https://go.microsoft.com/fwlink/?linkid=2068602"
    $wvdOutFile = "$env:USERPROFILE\Downloads\RemoteDesktop_x64.msi"
}
elseif($OSArchitecture -eq "32-bit"){
    $wvdDownloadURI = "https://go.microsoft.com/fwlink/?linkid=2098960"
    $wvdOutFile = "$env:USERPROFILE\Downloads\RemoteDesktop_x32.msi"
}
elseif($OSArchitecture -eq "ARM 64-bit Processor"){
    $wvdDownloadURI = "https://go.microsoft.com/fwlink/?linkid=2098961"
    $wvdOutFile = "$env:USERPROFILE\Downloads\RemoteDesktop_xARM64.msi"
}
else{
    Write-Host `t"OS Architecture not found" -ForegroundColor Red
    Break
}

# Download WVD client
#Write-Host `t"Downloading Windows Virtual Desktop Client" -BackgroundColor Blue
try{
    Invoke-WebRequest -Uri $wvdDownloadURI -OutFile $wvdOutFile
}catch{
    Write-Host `t"Download failed" -ForegroundColor Red
}

# Install WVD client
#Write-Host `t"Installing Windows Virtual Desktop Client" -BackgroundColor Blue
try{
    Start-Process -FilePath "msiexec.exe" -Wait -ArgumentList "/i `"$wvdOutFile`" /passive ALLUSERS=2 MSIINSTALLPERUSER=1"
}catch{
    Write-Host `t"Installation failed" -ForegroundColor Red
}

# Cleanup
#Write-Host `t"Cleanup: Removing downloaded files" -BackgroundColor Blue
try{
    #Remove WVD MSI
    Remove-Item -Path $wvdOutFile

    #Remove cert files
    Remove-Item -Path $rootCertOutFile
    Remove-Item -Path $intermediateCertOutFile

}catch{
    Write-Host `t"Cleanup failed" -ForegroundColor Red
}

#Pre-req checks
$warningFlag = 0
$warningMessage = @"
Installation completed with warnings:
======================================

"@

## Check if client can connect to VA ADFS over port 49443
# $testADFS = Test-NetConnection -port 49443 prod.adfs.federation.va.gov -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
# if(!($testADFS).TcpTestSucceeded)
# {
#     $warningFlag++
#     $warningMessage += "[*]  Connection to ADFS failed. Please notify the helpdesk.`n" 
# }

## Check if client PC is domain joined to a domain other than va.gov. If that user 
if((Get-WmiObject -Class Win32_ComputerSystem).PartofDomain){
    $domainName = (Get-WmiObject -Class Win32_ComputerSystem).Domain
    if($domainName -notlike "*va.gov*"){
        if(!((certutil -v -store -ent ntauth) -match "VA-Internal-S2-ICA1-v1")){
            $warningFlag++
            $warningMessage += "[*]  System is domain joined to a domain other than `"va.gov`". Authentication to Windows Virtual Desktop will fail. Machine is joined to domain: $($domainName). Please notify the helpdesk for assistance.`n"
            #Write-Warning "Machine is joined to domain: $($domainName)"
        }
    }
}

#Installation Complete
if($warningFlag -ge 1){
    Write-Host $warningMessage
}else{
    Write-Host `t"Installation completed. Opening application." -BackgroundColor DarkGreen
    
    #Open The "Remote Desktop" app with the ARM (Spring release) workspace URL
    Start-Process "ms-rd:subscribe?url=https://rdweb.wvd.microsoft.com/api/arm/feeddiscovery"
}