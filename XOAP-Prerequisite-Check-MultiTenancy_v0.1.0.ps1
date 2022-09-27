<#
	.SYNOPSIS
		The Script will gather Information of your device which are related to XOAP in order to function properly and determine areas which may need to be worked on / clarified.

	.DESCRIPTION
		The Script will gather the following Information
        - Node Name
        - Network IP addresses
        - Operating System Information
        - PowerShell version
        - Configured proxy for
            - Internet Settings
            - .NET Framework
        - Check Internet access to XOAP and its components
        A .zip compressed file named "XOAP" will be created in the temporary folder (C:\Users\***\APPDATA\Local\Temp) which contains the XOAP.log with the aboved mentioned gathered Info.

	.PARAMETER  XOAPURL
		Enter XOAP URL to be checked.
        For example: "65637224.xoss.io"

	.EXAMPLE
        & '.\XOAP - Prerequisite Check.ps1'
        & '.\XOAP - Prerequisite Check.ps1' -XOAPURL "65637224.xoap.io"

	.NOTES
		For more information about advanced functions, call Get-Help with any
		of the topics in the links listed below.
		File Name  : XOAP-Prerequisite-Check-MultiTenancy_v0.1.0  
    	Author     : RIS AG - info@xoap.io 
#>
#Requires -RunAsAdministrator

$LogPath = "$env:Systemdrive\XOAP"
$LogFile = "$Logpath\XOAP.log"

if (!(Test-Path "$LogPath")) {
    New-Item -Path "$LogPath" -ItemType Directory -Force
}

Start-Transcript -Path $LogFile -Append
Clear-Host

Write-Host "___________________________________________________________________________"
Write-Host "DSC Information" -ForegroundColor green
(Get-DscLocalConfigurationManager).ConfigurationDownloadManagers

Write-Host "___________________________________________________________________________"
Write-Host "IP-Address Information" -ForegroundColor green
Write-Host ""
$IPAddressNEW = Get-NetIPAddress
foreach ($ip in $IPAddressNEW) {
    Write-Host "Interface: "$IPAddressNEW.IndexOf($ip) "IPAddress: " $ip.IPAddress
    Write-Host "Interface: " $IPAddressNEW.IndexOf($ip) "AddressFamily: " $ip.AddressFamily `n
}

Write-Host "___________________________________________________________________________"
Write-Host "OS Information" -ForegroundColor green
$OperatingSystemInfo = Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber, OsServicePackMajorVersion, OsServicePackMinorVersion, CsDNSHostName, BiosFirmwareType, WindowsCurrentVersion, OsLocalDateTime, OsLanguage, TimeZone, KeyboardLayout
Write-Host "`nOS Information: " $OperatingSystemInfo

Write-Host "___________________________________________________________________________"
Write-Host "Microsoft.NET TLS1.2" -ForegroundColor green
$TLS1 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' | Select-Object -Property "SchUseStrongCrypto"
$TLS2 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' | Select-Object -Property "SchUseStrongCrypto"
$TLS3 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v2.0.50727' | Select-Object -Property "SchUseStrongCrypto"

Write-Host "`n.NetFrameworkv4.0: $TLS1"
Write-Host ".NetFrameworkv4.0x64" $TLS2 
Write-Host ".NetFrameworkv2.0" $TLS3

Write-Host "___________________________________________________________________________"
Write-Host "Microsoft.NET Framework Proxy" -ForegroundColor green

$MicrosoftNETProxy64 = Get-Content -Path "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config" | Select-String "proxyaddress"
$MicrosoftNETProxy = Get-Content -Path "C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\machine.config" | Select-String "proxyaddress"

Write-Host "`nMicrosoft.NET Proxy settings x64: "$MicrosoftNETProxy64
Write-Host "Microsoft.NET Proxy settings: "$MicrosoftNETProxy

Write-Host "___________________________________________________________________________"
Write-Host "Firewall Configuration" -ForegroundColor green

Get-NetFirewallProfile
Get-NetFirewallPortFilter

Write-Host "___________________________________________________________________________"
Write-Host "PowerShell Modules" -ForegroundColor green

# folders where PowerShell looks for modules:
$paths = $env:PSModulePath -split ';'
# finding actual module folders
$modules = Get-ChildItem -Path $paths -Depth 0 -Directory | Sort-Object -Property Name

$modules | 
Select-Object -Property Name, @{N='Parent';E={$_.Parent.FullName}}, FullName #|
#Out-GridView -Title 'Select module(s) to permanently delete' -PassThru |
#Out-GridView -Title 'Do you REALLY want to remove the modules below? CTRL+A and OK to confirm' -PassThru |
#Remove-Item -Path { $_.FullName } -Recurse -Force -WhatIf # remove -WhatIf to actually delete (as always at own risk)

$env:PSModulePath

Write-Host "___________________________________________________________________________"
Write-Host "PowerShell Profiles" -ForegroundColor green

$PROFILE | Format-List -Force

Write-Host "___________________________________________________________________________"
Write-Host "DSC Resources" -ForegroundColor green

Get-DSCResource

Write-Host "___________________________________________________________________________"
Write-Host "Check Access to Sites" -ForegroundColor green
$URLs = @{
    DSCAPI = "https://configuration-management.api.dev.xoap.io/ping"
    PackageAPI = "https://application-management.api.dev.xoap.io/ping"
    XOAP = "https://app.dev.xoap.io"
}

foreach ($url in $URLs.Keys){
    
    $value = $URLs[$url]
    Write-Host "$url - $($URLs[$url])"-ForegroundColor green
    #$ErrorActionPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $value -UseBasicParsing -ErrorAction SilentlyContinue
}

Write-Host "___________________________________________________________________________"
Write-Host "User Proxy" -ForegroundColor green
$Proxy = Get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select-Object ProxyEnable,ProxyServer,ProxyOverride
Write-Host "
Enabled: $($Proxy.ProxyEnable)
Server: $($Proxy.ProxyServer)
Override: $($Proxy.ProxyOverride)
"

Write-Host "___________________________________________________________________________"
Write-Host "User Proxy (System)" -ForegroundColor green
$Proxy = Get-ItemProperty -Path "Registry::HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select-Object ProxyEnable,ProxyServer,ProxyOverride
Write-Host "
Enabled: $($Proxy.ProxyEnable)
Server: $($Proxy.ProxyServer)
Override: $($Proxy.ProxyOverride)
"

Stop-Transcript -ErrorAction SilentlyContinue

Write-Host "Prerequisite check has finished! a zip compressed file named `"XOAP`" has been created in $systemdrive\XOAP"

Compress-Archive -Path $LogPath -DestinationPath $LogPath -Force
Remove-Item -Path $LogPath -Recurse -Force
