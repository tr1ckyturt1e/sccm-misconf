# SCCM Red Team Security Audit Script
# Author: Red Team / Penetration Testing
# Objective: Identify misconfigurations, vulnerabilities, and attack paths in Microsoft SCCM
# Note: This script is non-intrusive and does not cause downtime.

Write-Host "🚨 Starting SCCM Red Team Security Audit..." -ForegroundColor Red

# Ensure Script is Running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "⚠️ Please run this script as Administrator." -ForegroundColor Red
    exit
}

# Check if SCCM is Installed
function Check-SCCMInstallation {
    if (Test-Path "HKLM:\Software\Microsoft\SMS") {
        Write-Host "[✔] SCCM is installed." -ForegroundColor Green
    } else {
        Write-Host "[X] SCCM not found. Exiting..." -ForegroundColor Red
        exit
    }
}

# Identify SCCM Server, Site Code, and Installation Details
function Identify-SCCM {
    $site = Get-WmiObject -Namespace "root\SMS" -Class SMS_ProviderLocation -ErrorAction SilentlyContinue
    if ($site) {
        Write-Host "[✔] SCCM Site Server: $($site.Machine)" -ForegroundColor Green
        Write-Host "[✔] SCCM Site Code: $($site.SiteCode)" -ForegroundColor Yellow
    }
}

# Check if SCCM Uses Insecure HTTP
function Check-HTTPUsage {
    $httpSetting = Get-ItemProperty "HKLM:\Software\Microsoft\SMS\DP" -ErrorAction SilentlyContinue
    if ($httpSetting -and $httpSetting.HTTPSRequired -eq 0) {
        Write-Host "[!] SCCM is using HTTP instead of HTTPS. Weak encryption detected!" -ForegroundColor Red
    } else {
        Write-Host "[✔] SCCM is using HTTPS." -ForegroundColor Green
    }
}

# Extract SQL Credentials from Registry
function Extract-SQLCreds {
    $sqlPath = "HKLM:\SOFTWARE\Microsoft\SMS\SQL Server"
    if (Test-Path $sqlPath) {
        $sqlInstance = (Get-ItemProperty $sqlPath).DatabaseServer
        Write-Host "[✔] SCCM SQL Server Found: $sqlInstance" -ForegroundColor Yellow
        $creds = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SMS" | Select-Object *sql*
        if ($creds) {
            Write-Host "[!] SCCM Database Credentials Found:" -ForegroundColor Red
            $creds | Format-Table -AutoSize
        }
    }
}

# Check if Client Push Installation is Enabled
function Check-ClientPush {
    $clientPush = Get-WmiObject -Namespace "root\SMS" -Class SMS_SCI_ClientComp -ErrorAction SilentlyContinue
    if ($clientPush -and $clientPush.EnableClientPush -eq 1) {
        Write-Host "[!] Client Push Installation is enabled. Lateral movement risk detected!" -ForegroundColor Red
    } else {
        Write-Host "[✔] Client Push is disabled." -ForegroundColor Green
    }
}

# Check SQL Permissions
function Check-SQLPermissions {
    $query = "SELECT name, type_desc, is_disabled FROM sys.sql_logins WHERE type_desc='SQL_LOGIN'"
    $sqlInstance = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SMS\SQL Server").DatabaseServer
    if ($sqlInstance) {
        $result = Invoke-Sqlcmd -ServerInstance $sqlInstance -Query $query -ErrorAction SilentlyContinue
        if ($result) {
            Write-Host "[✔] SQL Logins Identified:" -ForegroundColor Green
            $result | Format-Table -AutoSize
        }
    }
}

# Check SCCM Service Account Privileges
function Check-ServiceAccountPrivileges {
    $sccmServices = Get-WmiObject -Namespace "root\cimv2" -Class Win32_Service | Where-Object { $_.Name -match "sms" }
    foreach ($service in $sccmServices) {
        Write-Host "[✔] SCCM Service: $($service.Name)" -ForegroundColor Yellow
        Write-Host "[!] Service Account: $($service.StartName)" -ForegroundColor Cyan
    }
}

# Check Client Policies
function Check-ClientPolicies {
    $policies = Get-WmiObject -Namespace "root\CCM\Policy" -Class CCM_PolicyCache -ErrorAction SilentlyContinue
    if ($policies) {
        Write-Host "[✔] Client Policies Found:" -ForegroundColor Green
        $policies | Select-Object PolicyID, PolicyType, PolicySource | Format-Table -AutoSize
    }
}

# Check if SCCM Admins Have Local Admin Rights on Clients
function Check-LocalAdminOnClients {
    $localAdmins = Get-WmiObject -Class Win32_GroupUser -Filter "GroupComponent='Win32_Group.Domain=`'Administrators`''"
    if ($localAdmins) {
        Write-Host "[!] SCCM Admins Have Local Admin Rights on Clients!" -ForegroundColor Red
        $localAdmins | Format-Table -AutoSize
    } else {
        Write-Host "[✔] SCCM Admins do not have local admin rights on clients." -ForegroundColor Green
    }
}

# Enumerate SCCM Site System Roles
function Enum-SCCMSiteRoles {
    $siteRoles = Get-WmiObject -Namespace "root\SMS" -Class SMS_SCI_Role
    if ($siteRoles) {
        Write-Host "[✔] SCCM Site System Roles Identified:" -ForegroundColor Green
        $siteRoles | Select-Object RoleName, ServerName | Format-Table -AutoSize
    }
}

# Enumerate SCCM Admins (T1078)
function Enum-SCCMAdmins {
    $sccmAdmins = Get-WmiObject -Namespace "root\SMS" -Class SMS_User -ErrorAction SilentlyContinue
    if ($sccmAdmins) {
        Write-Host "[✔] SCCM Admins Identified:" -ForegroundColor Yellow
        $sccmAdmins | Select-Object UserName | Format-Table -AutoSize
    } else {
        Write-Host "[!] No SCCM Admins Found." -ForegroundColor Red
    }
}

# Scan SCCM Log Files for Credentials or Sensitive Data
function Scan-SCCMLogs {
    $logPath = "C:\Program Files\Microsoft Configuration Manager\Logs"
    if (Test-Path $logPath) {
        Write-Host "[✔] Checking SCCM logs for credential leaks..." -ForegroundColor Yellow
        Get-ChildItem -Path $logPath -Filter "*.log" -Recurse | ForEach-Object {
            if (Select-String -Path $_.FullName -Pattern "password|pwd|authentication failed" -Quiet) {
                Write-Host "[!] Credential Leak in Log File: $($_.FullName)" -ForegroundColor Red
            }
        }
    }
}

# Check SCCM WMI Persistence
function Check-WMIPersistence {
    $wmiFilters = Get-WmiObject -Namespace "root\Subscription" -Class __EventFilter
    if ($wmiFilters) {
        Write-Host "[!] Possible WMI Persistence Found:" -ForegroundColor Red
        $wmiFilters | Select-Object Name, Query | Format-Table -AutoSize
    }
}

# Check Registry-Based Persistence
function Check-RegistryPersistence {
    $regKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($key in $regKeys) {
        if (Test-Path $key) {
            $entries = Get-ItemProperty -Path $key
            if ($entries) {
                Write-Host "[!] Registry-Based Persistence Detected:" -ForegroundColor Red
                $entries | Format-Table -AutoSize
            }
        }
    }
}

# Check SCCM Task Sequences for Misuse (T1053.005)
function Check-SCCMTaskSequences {
    $taskSequences = Get-WmiObject -Namespace "root\SMS\Site_$($env:COMPUTERNAME)" -Class SMS_TaskSequencePackage -ErrorAction SilentlyContinue
    if ($taskSequences) {
        Write-Host "[✔] SCCM Task Sequences Found (Potential Hijack Targets):" -ForegroundColor Yellow
        $taskSequences | Select-Object PackageID, Name, Version | Format-Table -AutoSize
    } else {
        Write-Host "[✔] No SCCM Task Sequences Found." -ForegroundColor Green
    }
}

# Check CMTrace Execution for Lateral Movement (T1569.002)
function Check-CMTraceExecution {
    $cmtracePath = "C:\Program Files\Microsoft Configuration Manager\tools\CMTrace.exe"
    if (Test-Path $cmtracePath) {
        Write-Host "[!] CMTrace found. Potential lateral movement vector!" -ForegroundColor Red
    } else {
        Write-Host "[✔] CMTrace not found on this system." -ForegroundColor Green
    }
}

# Execute All Checks
Check-SCCMInstallation
Identify-SCCM
Check-HTTPUsage
Extract-SQLCreds
Check-ClientPush
Check-SQLPermissions
Check-ServiceAccountPrivileges
Check-ClientPolicies
Check-LocalAdminOnClients
Enum-SCCMSiteRoles
Scan-SCCMLogs
Check-WMIPersistence
Check-RegistryPersistence
Check-SCCMTaskSequences
Check-CMTraceExecution
Enum-SCCMAdmins

Write-Host "🚨 SCCM Red Team Security Audit Completed." -ForegroundColor Red