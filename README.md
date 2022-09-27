# Getting started

This repository consists of scripts that gather environment specific information.

The purpose is to check prerequisites that are necessary to access our XOAP platform.

We are gathering the following data:

- DSC Information
- IP-Address Information
- OS Information
- Microsoft.NET TLS1.2
- Microsoft.NET Framework Proxy
- Firewall Configuration
- PowerShell Modules
- PowerShell Profiles
- DSC Resources
- Check Access to our APIs
- User Proxy

## Dedicated environments (deprecated)

Please run the following script on a Windows Node in your environment:

```PowerShell
XOAP-Prerequisite-Check-Dedicated_v0.1.1.ps1
```

## my.xoap.io environments

Please run the following script on a Windows Node in your environment:

```PowerShell
XOAP-Prerequisite-Check-MultiTenancy_v0.1.1.ps1
```

In both cases a zip File is created in $env:systemroot.