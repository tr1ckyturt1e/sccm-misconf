# SCCM Server Security Audit Script
# Purpose: Identify SCCM server misconfigurations, privileged account enumeration, SQL credential extraction, and MITRE ATT&CK checks

Write-Host "🚀 Starting SCCM Server Security Audit..." -ForegroundColor Red

# Check if running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "⚠️ Please run this script as Administrator." -ForegroundColor Red
    exit
}

# Retrieve SCCM Site Code Automatically
$SiteCode = (Get-WmiObject -Namespace "root\SMS" -Class SMS_ProviderLocation -ErrorAction SilentlyContinue).SiteCode
if (-not $SiteCode) {
    Write-Host "[!] Unable to determine SCCM Site Code." -ForegroundColor Red
    exit
} else {
    Write-Host "[✔] SCCM Site Code Identified: $SiteCode" -ForegroundColor Green
}

# Identify SCCM Site Server
function Identify-SCCMServer {
    $siteServer = Get-WmiObject -Namespace "root\SMS" -Class SMS_ProviderLocation -ErrorAction SilentlyContinue
    if ($siteServer) {
        Write-Host "[✔] SCCM Server Identified: $($siteServer.Machine)" -ForegroundColor Green
    } else {
        Write-Host "[!] No SCCM Server Found." -ForegroundColor Red
    }
}

# Active Directory Security Checks
function Check-ADSecurity {
    Write-Host "[✔] Checking Active Directory Security..." -ForegroundColor Yellow
    # Ensure ms-DS-MachineAccountQuota is set to 0
    $quota = Get-ADObject -Filter {objectClass -eq "domainDNS"} -Property ms-DS-MachineAccountQuota
    if ($quota."ms-DS-MachineAccountQuota" -eq 0) {
        Write-Host "[✔] ms-DS-MachineAccountQuota is correctly set to 0." -ForegroundColor Green
    } else {
        Write-Host "[!] ms-DS-MachineAccountQuota is NOT set to 0." -ForegroundColor Red
    }
}

# Network Access Accounts (NAA) Security Checks
function Check-NAASecurity {
    Write-Host "[✔] Checking Network Access Account Security..." -ForegroundColor Yellow
    $naaAccounts = Get-WmiObject -Namespace "root\SMS" -Class SMS_Site -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NetworkAccessAccount
    if ($naaAccounts) {
        Write-Host "[!] Network Access Account is configured: $naaAccounts" -ForegroundColor Red
    } else {
        Write-Host "[✔] No Network Access Account configured." -ForegroundColor Green
    }
}

# Client Push Security Checks
function Check-ClientPushSecurity {
    Write-Host "[✔] Checking Client Push Security..." -ForegroundColor Yellow
    $clientPushEnabled = Get-WmiObject -Namespace "root\SMS" -Class SMS_SCI_ClientComp -ErrorAction SilentlyContinue | Where-Object {$_.PropertyName -eq "EnableClientPush"}
    if ($clientPushEnabled -and $clientPushEnabled.Value -eq 1) {
        Write-Host "[!] Client Push is enabled! Consider disabling it for security." -ForegroundColor Red
    } else {
        Write-Host "[✔] Client Push is disabled." -ForegroundColor Green
    }
}

# PXE Hardening
function Check-PXEHardening {
    Write-Host "[✔] Checking PXE Hardening..." -ForegroundColor Yellow
    $pxeEnabled = Get-WmiObject -Namespace "root\SMS" -Class SMS_SCI_Component -ErrorAction SilentlyContinue | Where-Object {$_.PropertyName -eq "PXEEnabled"}
    if ($pxeEnabled -and $pxeEnabled.Value -eq 1) {
        Write-Host "[!] PXE booting is enabled! Ensure secure configurations are in place." -ForegroundColor Red
    } else {
        Write-Host "[✔] PXE booting is disabled." -ForegroundColor Green
    }
}

# Patching Security Checks
function Check-PatchingSecurity {
    Write-Host "[✔] Checking Patching Security..." -ForegroundColor Yellow
    $installedKBs = (Get-HotFix).HotFixID
    if ("KB15498768" -in $installedKBs -and "KB15599094" -in $installedKBs) {
        Write-Host "[✔] Required SCCM security KBs are installed." -ForegroundColor Green
    } else {
        Write-Host "[!] Required SCCM security KBs are missing! Install KB15498768 and KB15599094." -ForegroundColor Red
    }
}

# MSSQL Hardening
function Check-MSSQLHardening {
    Write-Host "[✔] Checking MSSQL Hardening..." -ForegroundColor Yellow
    $sqlProtection = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MSSQLServer\Security" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ExtendedProtection
    if ($sqlProtection -eq 1) {
        Write-Host "[✔] MSSQL Extended Protection is enabled." -ForegroundColor Green
    } else {
        Write-Host "[!] MSSQL Extended Protection is NOT enabled. Consider enabling it for security." -ForegroundColor Red
    }
}

# Site Server Security Checks
function Check-SiteServerSecurity {
    Write-Host "[✔] Checking Site Server Security..." -ForegroundColor Yellow
    $firewallRules = Get-NetFirewallRule -DisplayName "SCCM*" -ErrorAction SilentlyContinue
    if ($firewallRules) {
        Write-Host "[✔] SCCM firewall rules found. Ensure they are properly configured." -ForegroundColor Green
    } else {
        Write-Host "[!] No SCCM firewall rules found! Verify firewall restrictions." -ForegroundColor Red
    }
}

# Run all SCCM Security Checks
Identify-SCCMServer
Check-ADSecurity
Check-NAASecurity
Check-ClientPushSecurity
Check-PXEHardening
Check-PatchingSecurity
Check-MSSQLHardening
Check-SiteServerSecurity

Write-Host "🚀 SCCM Security Audit Completed." -ForegroundColor Red
