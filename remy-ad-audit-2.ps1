# Remote-ADAudit.ps1
# Modified version of remy-ad-audit.ps1 optimized for remote execution from non-domain systems
# Usage: .\Remote-ADAudit.ps1 -DomainController dc.domain.com -DomainName domain.com [-Credential $cred]

param (
    [Parameter(Mandatory=$true, HelpMessage="Enter the domain controller FQDN or IP")]
    [string]$DomainController,
    
    [Parameter(Mandatory=$true, HelpMessage="Enter the domain name (e.g., domain.local)")]
    [string]$DomainName,
    
    [Parameter(Mandatory=$false, HelpMessage="Domain credentials (will prompt if not provided)")]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string[]]$Modules = @("all"),
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\ADAudit-Results"
)

# Add this after the parameters to prompt for credentials if not provided
if (-not $Credential) {
    $Credential = Get-Credential -Message "Enter domain administrator credentials"
}

# Banner
Write-Host @"
 ________________________________________________________________


8888888b.                                             d8888 8888888b.  
888   Y88b                                           d88888 888  "Y88b 
888    888                                          d88P888 888    888 
888   d88P .d88b.  88888b.d88b.  888  888          d88P 888 888    888 
8888888P" d8P  Y8b 888 "888 "88b 888  888         d88P  888 888    888 
888 T88b  88888888 888  888  888 888  888        d88P   888 888    888 
888  T88b Y8b.     888  888  888 Y88b 888       d8888888888 888  .d88P 
888   T88b "Y8888  888  888  888  "Y88888      d88P     888 8888888P"  
                                      888                              
                                 Y8b d88P                              
                                  "Y88P"                               
  
 REMOTE-AD-AUDIT: Remote-Only Active Directory Audit Toolkit
 Version: 1.0 | Mode: Remote w/ Domain Credentials via Jump Box

 🔍 Coverage: Remote-compatible AD enumeration and security assessment
 📊 Compatible with NIST 800-53, 800-171, SOX, HIPAA, CIS, ISO27001
 📁 Reports: HTML Dashboards, CSV Exports, Remediation Guidance
 ⚠️  Ensure authorization before scanning or auditing production AD
 ________________________________________________________________
"@

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
    Write-Host "[+] Created output directory: $OutputPath"
}

# Initialize common parameters for all AD cmdlets
$ADParams = @{
    Server = $DomainController
}

if ($Credential) {
    $ADParams.Credential = $Credential
    Write-Host "[+] Using provided credentials for authentication"
} else {
    Write-Host "[+] Using current user credentials (if prompted, enter domain credentials)"
}

# Check module availability first
$requiredModules = @("ActiveDirectory")
$missingModules = @()

foreach ($module in $requiredModules) {
    if (!(Get-Module -Name $module -ListAvailable)) {
        $missingModules += $module
    }
}

if ($missingModules.Count -gt 0) {
    Write-Warning "[-] Missing required modules: $($missingModules -join ", ")"
    Write-Host "[*] Attempting to install missing modules..."
    
    foreach ($module in $missingModules) {
        try {
            if ($module -eq "ActiveDirectory") {
                Write-Host "[+] The ActiveDirectory module is part of RSAT tools and must be installed via Windows Features."
                Write-Host "    Use: 'Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'"
            } else {
                Install-Module -Name $module -Force -AllowClobber
                Write-Host "[+] Successfully installed $module"
            }
        } catch {
            Write-Warning "[-] Failed to install $module. Error: $_"
        }
    }
}

# Import required modules
foreach ($module in $requiredModules) {
    if (Get-Module -Name $module -ListAvailable) {
        Import-Module $module -Force
        Write-Host "[+] Imported module: $module"
    }
}

# Test connection to domain controller
function Test-DCConnection {
    Write-Host "[+] Testing connectivity to domain controller: $DomainController"
    
    if (Test-Connection -ComputerName $DomainController -Count 2 -Quiet) {
        Write-Host "[+] Domain Controller $DomainController is reachable."
        return $true
    } else {
        Write-Warning "[-] Cannot reach Domain Controller $DomainController."
        return $false
    }
}

# Execute AD Command with proper parameters
function Execute-ADCommand {
    param(
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$Command
    )
    
    try {
        & $Command @ADParams
        return $true
    } catch {
        Write-Warning "[-] Command failed: $_"
        return $false
    }
}

# Basic domain information gathering
function Get-BasicDomainInfo {
    Write-Host "[+] Gathering basic domain information..."
    
    try {
        $domainInfo = Execute-ADCommand -Command { Get-ADDomain }
        if ($domainInfo) {
            $domainInfo | Out-File -FilePath (Join-Path $OutputPath "Domain_Info.txt")
            return $true
        }
    } catch {
        Write-Warning "[-] Failed to get domain info: $_"
    }
    
    return $false
}

# Gather password policy
function Get-PasswordPolicy {
    Write-Host "[+] Gathering password policy..."
    
    try {
        $policy = Execute-ADCommand -Command { Get-ADDefaultDomainPasswordPolicy }
        if ($policy) {
            $policy | Format-List | Out-File -FilePath (Join-Path $OutputPath "Password_Policy.txt")
            
            # Extract key policy settings for summary
            $policyDetails = [PSCustomObject]@{
                MinPasswordLength = $policy.MinPasswordLength
                PasswordHistoryCount = $policy.PasswordHistoryCount
                ComplexityEnabled = $policy.ComplexityEnabled
                MaxPasswordAge = $policy.MaxPasswordAge
                MinPasswordAge = $policy.MinPasswordAge
                LockoutThreshold = $policy.LockoutThreshold
                LockoutDuration = $policy.LockoutDuration
            }
            
            $policyDetails | Export-Csv -Path (Join-Path $OutputPath "Password_Policy_Summary.csv") -NoTypeInformation
            Write-Host "    [✓] Password policy saved to Password_Policy.txt and Password_Policy_Summary.csv"
            return $true
        }
    } catch {
        Write-Warning "[-] Failed to get password policy: $_"
    }
    
    return $false
}

# Get privileged group membership
function Get-PrivilegedGroups {
    Write-Host "[+] Gathering privileged group membership..."
    
    $groups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
        "DNSAdmins"
    )
    
    $successCount = 0
    
    foreach ($group in $groups) {
        try {
            $groupObject = Execute-ADCommand -Command { Get-ADGroup -Identity $group }
            if (!$groupObject) { continue }
            
            Write-Host "    [*] Processing group: $group"
            $members = Execute-ADCommand -Command { Get-ADGroupMember -Identity $group -Recursive }
            
            if ($members) {
                $outputFile = Join-Path $OutputPath "$($group.Replace(' ', '_')).txt"
                $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName |
                    Format-Table -AutoSize | Out-File -FilePath $outputFile
                
                # Create CSV version for easier analysis
                $csvFile = Join-Path $OutputPath "$($group.Replace(' ', '_')).csv"
                $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName |
                    Export-Csv -Path $csvFile -NoTypeInformation
                
                Write-Host "    [✓] $($members.Count) members found in $group"
                $successCount++
            } else {
                Write-Host "    [!] No members found in '$group' or access denied"
            }
        } catch {
            $errorMessage = $_.Exception.Message
            Write-Warning "    [-] Failed to get members of '$group': $errorMessage"
        }
    }
    
    if ($successCount -gt 0) {
        return $true
    } else {
        return $false
    }
}

# Get users with Kerberoastable SPNs
function Get-KerberoastableUsers {
    Write-Host "[+] Enumerating Kerberoastable users (SPN accounts)..."
    
    try {
        $spnAccounts = Execute-ADCommand -Command { 
            Get-ADUser -Filter { ServicePrincipalName -like "*" -and Enabled -eq $true } -Properties ServicePrincipalName, LastLogonDate, PasswordLastSet 
        }
        
        if ($spnAccounts) {
            $outputPath = Join-Path $OutputPath "Kerberoastable_Users.txt"
            $csvPath = Join-Path $OutputPath "Kerberoastable_Users.csv"
            
            $spnAccounts | Select-Object Name, SamAccountName, ServicePrincipalName, LastLogonDate, PasswordLastSet |
                Format-Table -AutoSize | Out-File -FilePath $outputPath
                
            $spnAccounts | Select-Object Name, SamAccountName, ServicePrincipalName, LastLogonDate, PasswordLastSet |
                Export-Csv -Path $csvPath -NoTypeInformation
                
            Write-Host "    [✓] Found $($spnAccounts.Count) accounts with SPNs"
            return $true
        } else {
            Write-Host "    [!] No Kerberoastable users found or access denied"
        }
    } catch {
        Write-Warning "[-] Failed to enumerate Kerberoastable users: $_"
    }
    
    return $false
}

# Get users vulnerable to ASREPRoast (accounts with Kerberos pre-auth disabled)
function Get-ASREPRoastableUsers {
    Write-Host "[+] Enumerating ASREPRoastable users (no pre-auth required)..."
    
    try {
        $asrepUsers = Execute-ADCommand -Command { 
            Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } -Properties DoesNotRequirePreAuth, LastLogonDate, PasswordLastSet
        }
        
        $outputPath = Join-Path $OutputPath "ASREPRoastable_Users.txt"
        $csvPath = Join-Path $OutputPath "ASREPRoastable_Users.csv"
        
        if ($asrepUsers) {
            $asrepUsers | Select-Object Name, SamAccountName, DistinguishedName, LastLogonDate, PasswordLastSet | 
                Format-Table -AutoSize | Out-File -FilePath $outputPath
                
            $asrepUsers | Select-Object Name, SamAccountName, DistinguishedName, LastLogonDate, PasswordLastSet | 
                Export-Csv -Path $csvPath -NoTypeInformation
                
            Write-Host "    [✓] Found $($asrepUsers.Count) accounts with pre-auth disabled - VULNERABLE TO ASREPROAST"
            return $true
        } else {
            "No ASREPRoastable users found." | Out-File -FilePath $outputPath
            Write-Host "    [✓] No ASREPRoastable users found - GOOD SECURITY POSTURE"
            return $true
        }
    } catch {
        Write-Warning "[-] Failed to enumerate ASREPRoastable users: $_"
    }
    
    return $false
}

# Get domains trusts
function Get-DomainTrusts {
    Write-Host "[+] Gathering domain trust relationships..."
    
    try {
        $trusts = Execute-ADCommand -Command { Get-ADTrust -Filter * }
        
        $outputPath = Join-Path $OutputPath "Domain_Trusts.txt"
        $csvPath = Join-Path $OutputPath "Domain_Trusts.csv"
        
        if ($trusts) {
            $trusts | Select-Object Name, Direction, DisallowTransivity, ForestTransitive, IntraForest, TrustType, UsesAESKeys, UsesRC4Encryption | 
                Format-Table -AutoSize | Out-File -FilePath $outputPath
                
            $trusts | Select-Object Name, Direction, DisallowTransivity, ForestTransitive, IntraForest, TrustType, UsesAESKeys, UsesRC4Encryption | 
                Export-Csv -Path $csvPath -NoTypeInformation
                
            Write-Host "    [✓] Found $($trusts.Count) domain trust relationships"
            return $true
        } else {
            "No domain trusts found." | Out-File -FilePath $outputPath
            Write-Host "    [✓] No domain trusts found"
            return $true
        }
    } catch {
        Write-Warning "[-] Failed to retrieve trust relationships: $_"
    }
    
    return $false
}

# Get disabled and inactive accounts
function Get-DisabledAndInactiveAccounts {
    Write-Host "[+] Auditing disabled and inactive user accounts..."
    
    try {
        # Get disabled accounts
        $disabledUsers = Execute-ADCommand -Command { 
            Get-ADUser -Filter { Enabled -eq $false } -Properties SamAccountName, LastLogonDate, PasswordLastSet
        }
        
        # Get accounts that haven't logged in for 90+ days
        $cutoffDate = (Get-Date).AddDays(-90)
        $inactiveUsers = Execute-ADCommand -Command { 
            Get-ADUser -Filter { LastLogonDate -lt $cutoffDate -and Enabled -eq $true } -Properties SamAccountName, LastLogonDate, PasswordLastSet
        }
        
        $outputDisabled = Join-Path $OutputPath "Disabled_Accounts.txt"
        $outputInactive = Join-Path $OutputPath "Inactive_Accounts.txt"
        $csvDisabled = Join-Path $OutputPath "Disabled_Accounts.csv"
        $csvInactive = Join-Path $OutputPath "Inactive_Accounts.csv"
        
        if ($disabledUsers) {
            $disabledUsers | Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet | 
                Format-Table -AutoSize | Out-File -FilePath $outputDisabled
                
            $disabledUsers | Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet | 
                Export-Csv -Path $csvDisabled -NoTypeInformation
                
            Write-Host "    [✓] Found $($disabledUsers.Count) disabled accounts"
        } else {
            "No disabled accounts found." | Out-File -FilePath $outputDisabled
            Write-Host "    [✓] No disabled accounts found"
        }
        
        if ($inactiveUsers) {
            $inactiveUsers | Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet | 
                Format-Table -AutoSize | Out-File -FilePath $outputInactive
                
            $inactiveUsers | Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet | 
                Export-Csv -Path $csvInactive -NoTypeInformation
                
            Write-Host "    [✓] Found $($inactiveUsers.Count) inactive accounts (no logon for 90+ days)"
        } else {
            "No inactive accounts found." | Out-File -FilePath $outputInactive
            Write-Host "    [✓] No inactive accounts found (over 90 days)"
        }
        
        return $true
    } catch {
        Write-Warning "[-] Failed to gather disabled or inactive accounts: $_"
    }
    
    return $false
}

# Get recent changes (users and groups created in the last 30 days)
function Get-RecentChanges {
    Write-Host "[+] Auditing recently created users and groups (last 30 days)..."
    
    try {
        $since = (Get-Date).AddDays(-30)
        $newUsers = Execute-ADCommand -Command { 
            Get-ADUser -Filter { whenCreated -ge $since } -Properties whenCreated, DisplayName, Description
        }
        
        $newGroups = Execute-ADCommand -Command { 
            Get-ADGroup -Filter { whenCreated -ge $since } -Properties whenCreated, Description
        }
        
        $outputUsers = Join-Path $OutputPath "NewUsers_Last30Days.txt"
        $outputGroups = Join-Path $OutputPath "NewGroups_Last30Days.txt"
        $csvUsers = Join-Path $OutputPath "NewUsers_Last30Days.csv"
        $csvGroups = Join-Path $OutputPath "NewGroups_Last30Days.csv"
        
        if ($newUsers) {
            $newUsers | Select-Object Name, SamAccountName, DisplayName, whenCreated, Description | 
                Format-Table -AutoSize | Out-File -FilePath $outputUsers
                
            $newUsers | Select-Object Name, SamAccountName, DisplayName, whenCreated, Description | 
                Export-Csv -Path $csvUsers -NoTypeInformation
                
            Write-Host "    [✓] Found $($newUsers.Count) users created in the last 30 days"
        } else {
            "No users created in the last 30 days." | Out-File -FilePath $outputUsers
            Write-Host "    [✓] No users created in the last 30 days"
        }
        
        if ($newGroups) {
            $newGroups | Select-Object Name, GroupCategory, GroupScope, whenCreated, Description | 
                Format-Table -AutoSize | Out-File -FilePath $outputGroups
                
            $newGroups | Select-Object Name, GroupCategory, GroupScope, whenCreated, Description | 
                Export-Csv -Path $csvGroups -NoTypeInformation
                
            Write-Host "    [✓] Found $($newGroups.Count) groups created in the last 30 days"
        } else {
            "No groups created in the last 30 days." | Out-File -FilePath $outputGroups
            Write-Host "    [✓] No groups created in the last 30 days"
        }
        
        return $true
    } catch {
        Write-Warning "[-] Failed to audit recent user/group creation: $_"
    }
    
    return $false
}

# Get old OS machines
function Get-OldOSMachines {
    Write-Host "[+] Checking for old/outdated operating systems in AD..."
    
    try {
        $computers = Execute-ADCommand -Command { 
            Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate
        }
        
        $legacyOS = $computers | Where-Object { 
            $_.OperatingSystem -match 'Windows (2000|2003|XP|Vista|7|2008( R2)?)' -or
            ($_.OperatingSystem -match 'Windows Server 2012( R2)?' -and -not ($_.OperatingSystem -match 'Windows Server 2012 R2'))
        }
        
        $outputPath = Join-Path $OutputPath "Old_OS_Machines.txt"
        $csvPath = Join-Path $OutputPath "Old_OS_Machines.csv"
        
        if ($legacyOS) {
            $legacyOS | Select-Object Name, OperatingSystem, OperatingSystemVersion, LastLogonDate | 
                Format-Table -AutoSize | Out-File -FilePath $outputPath
                
            $legacyOS | Select-Object Name, OperatingSystem, OperatingSystemVersion, LastLogonDate | 
                Export-Csv -Path $csvPath -NoTypeInformation
                
            Write-Host "    [✓] Found $($legacyOS.Count) computers with outdated operating systems"
        } else {
            "No computers with outdated operating systems found." | Out-File -FilePath $outputPath
            Write-Host "    [✓] No outdated operating systems found - GOOD SECURITY POSTURE"
        }
        
        # Windows 10/11 without recent updates
        $oldW10 = $computers | Where-Object { 
            $_.OperatingSystem -match 'Windows 10' -and 
            ($_.OperatingSystemVersion -match '10.0 \(1[0-8][0-9]{2,}\)' -or $_.OperatingSystemVersion -match '10.0 \(19[0-9]{2,}\)')
        }
        
        $outputW10Path = Join-Path $OutputPath "Outdated_Windows10.txt"
        $csvW10Path = Join-Path $OutputPath "Outdated_Windows10.csv"
        
        if ($oldW10) {
            $oldW10 | Select-Object Name, OperatingSystem, OperatingSystemVersion, LastLogonDate | 
                Format-Table -AutoSize | Out-File -FilePath $outputW10Path
                
            $oldW10 | Select-Object Name, OperatingSystem, OperatingSystemVersion, LastLogonDate | 
                Export-Csv -Path $csvW10Path -NoTypeInformation
                
            Write-Host "    [✓] Found $($oldW10.Count) computers with outdated Windows 10 builds"
        } else {
            "No computers with outdated Windows 10 builds found." | Out-File -FilePath $outputW10Path
            Write-Host "    [✓] No outdated Windows 10 builds found"
        }
        
        return $true
    } catch {
        Write-Warning "[-] Failed to identify old OS machines: $_"
    }
    
    return $false
}

# Get users with AdminCount=1 who might have delegated rights removed
function Get-AdminSDHolderProtectedAccounts {
    Write-Host "[+] Identifying AdminSDHolder protected accounts..."
    
    try {
        $protectedAccounts = Execute-ADCommand -Command { 
            Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $true } -Properties AdminCount, ServicePrincipalName, LastLogonDate, PasswordLastSet, MemberOf
        }
        
        $outputPath = Join-Path $OutputPath "AdminSDHolder_Protected_Accounts.txt"
        $csvPath = Join-Path $OutputPath "AdminSDHolder_Protected_Accounts.csv"
        
        if ($protectedAccounts) {
            $protectedAccounts | Select-Object Name, SamAccountName, DistinguishedName, ServicePrincipalName, LastLogonDate, PasswordLastSet | 
                Format-Table -AutoSize | Out-File -FilePath $outputPath
                
            $protectedAccounts | Select-Object Name, SamAccountName, DistinguishedName, ServicePrincipalName, LastLogonDate, PasswordLastSet | 
                Export-Csv -Path $csvPath -NoTypeInformation
                
            Write-Host "    [✓] Found $($protectedAccounts.Count) accounts protected by AdminSDHolder (AdminCount=1)"
            
            # Extra check for service accounts with AdminCount=1 (high risk)
            $svcAccounts = $protectedAccounts | Where-Object { $_.ServicePrincipalName -ne $null }
            
            if ($svcAccounts) {
                $svcPath = Join-Path $OutputPath "AdminCount_ServiceAccounts.txt"
                $svcAccounts | Select-Object Name, SamAccountName, ServicePrincipalName | 
                    Format-Table -AutoSize | Out-File -FilePath $svcPath
                    
                Write-Host "    [!] WARNING: Found $($svcAccounts.Count) service accounts with AdminCount=1. High security risk!"
            }
        } else {
            "No accounts protected by AdminSDHolder (AdminCount=1) found." | Out-File -FilePath $outputPath
            Write-Host "    [✓] No AdminSDHolder protected accounts found"
        }
        
        return $true
    } catch {
        Write-Warning "[-] Failed to check AdminSDHolder protected accounts: $_"
    }
    
    return $false
}

# Check for accounts with SIDHistory (potential privilege escalation path)
function Get-SIDHistoryAccounts {
    Write-Host "[+] Checking for accounts with SIDHistory (potential privilege escalation)..."
    
    try {
        $sidHistoryAccounts = Execute-ADCommand -Command { 
            Get-ADUser -Filter { SIDHistory -like "*" } -Properties SIDHistory, Enabled, LastLogonDate, PasswordLastSet
        }
        
        $outputPath = Join-Path $OutputPath "SIDHistory_Accounts.txt"
        $csvPath = Join-Path $OutputPath "SIDHistory_Accounts.csv"
        
        if ($sidHistoryAccounts) {
            $sidHistoryAccounts | Select-Object Name, SamAccountName, Enabled, SIDHistory, LastLogonDate, PasswordLastSet | 
                Format-Table -AutoSize | Out-File -FilePath $outputPath
                
            $sidHistoryAccounts | Select-Object Name, SamAccountName, Enabled, SIDHistory, LastLogonDate, PasswordLastSet | 
                Export-Csv -Path $csvPath -NoTypeInformation
                
            Write-Host "    [✓] Found $($sidHistoryAccounts.Count) accounts with SIDHistory - POTENTIAL SECURITY RISK"
        } else {
            "No accounts with SIDHistory found." | Out-File -FilePath $outputPath
            Write-Host "    [✓] No accounts with SIDHistory found - GOOD SECURITY POSTURE"
        }
        
        return $true
    } catch {
        Write-Warning "[-] Failed to check accounts with SIDHistory: $_"
    }
    
    return $false
}

# Check for unconstrained Kerberos delegation
function Get-UnconstrainedDelegation {
    Write-Host "[+] Checking for computers with unconstrained Kerberos delegation..."
    
    try {
        $unconstrainedComputers = Execute-ADCommand -Command { 
            Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, OperatingSystem, LastLogonDate
        }
        
        $unconstrainedUsers = Execute-ADCommand -Command { 
            Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, LastLogonDate, PasswordLastSet
        }
        
        $outputComputersPath = Join-Path $OutputPath "Unconstrained_Delegation_Computers.txt"
        $csvComputersPath = Join-Path $OutputPath "Unconstrained_Delegation_Computers.csv"
        $outputUsersPath = Join-Path $OutputPath "Unconstrained_Delegation_Users.txt"
        $csvUsersPath = Join-Path $OutputPath "Unconstrained_Delegation_Users.csv"
        
        if ($unconstrainedComputers) {
            $unconstrainedComputers | Select-Object Name, DNSHostName, OperatingSystem, LastLogonDate | 
                Format-Table -AutoSize | Out-File -FilePath $outputComputersPath
                
            $unconstrainedComputers | Select-Object Name, DNSHostName, OperatingSystem, Enabled, LastLogonDate | 
                Export-Csv -Path $csvComputersPath -NoTypeInformation
                
            Write-Host "    [!] Found $($unconstrainedComputers.Count) computers with unconstrained delegation - SECURITY RISK"
        } else {
            "No computers with unconstrained delegation found." | Out-File -FilePath $outputComputersPath
            Write-Host "    [✓] No computers with unconstrained delegation found - GOOD SECURITY POSTURE"
        }
        
        if ($unconstrainedUsers) {
            $unconstrainedUsers | Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet | 
                Format-Table -AutoSize | Out-File -FilePath $outputUsersPath
                
            $unconstrainedUsers | Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet | 
                Export-Csv -Path $csvUsersPath -NoTypeInformation
                
            Write-Host "    [!] Found $($unconstrainedUsers.Count) users with unconstrained delegation - SEVERE SECURITY RISK"
        } else {
            "No users with unconstrained delegation found." | Out-File -FilePath $outputUsersPath
            Write-Host "    [✓] No users with unconstrained delegation found - GOOD SECURITY POSTURE"
        }
        
        return $true
    } catch {
        Write-Warning "[-] Failed to check for unconstrained delegation: $_"
    }
    
    return $false
}

# Generate HTML report with findings
function Generate-HTMLReport {
    Write-Host "[+] Generating HTML report with all findings..."
    
    $reportPath = Join-Path $OutputPath "AD_Audit_Report.html"
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Active Directory Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #2c3e50; margin-top: 30px; border-left: 4px solid #3498db; padding-left: 10px; }
        .finding { margin: 15px 0; padding: 15px; border-radius: 5px; }
        .critical { background-color: #f8d7da; border: 1px solid #f5c6cb; }
        .high { background-color: #fff3cd; border: 1px solid #ffeeba; }
        .medium { background-color: #d1ecf1; border: 1px solid #bee5eb; }
        .low { background-color: #d4edda; border: 1px solid #c3e6cb; }
        .secure { background-color: #d4edda; border: 1px solid #c3e6cb; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { text-align: left; padding: 8px; border: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Active Directory Security Audit Report</h1>
    <p><strong>Domain:</strong> $DomainName</p>
    <p><strong>Domain Controller:</strong> $DomainController</p>
    <p><strong>Report Generated:</strong> $reportDate</p>

    <h2>Summary of Findings</h2>
    <div>
        <table>
            <tr>
                <th>Category</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
"@

    # Check each output file to determine findings
    $findings = @()
    
    # Kerberoastable accounts
    $kerbFile = Join-Path $OutputPath "Kerberoastable_Users.csv"
    if (Test-Path $kerbFile) {
        $count = (Import-Csv $kerbFile | Measure-Object).Count
        if ($count -gt 0) {
            $findings += @"
            <tr class="high">
                <td>Kerberoastable Accounts</td>
                <td><span style="color: red; font-weight: bold;">HIGH RISK</span></td>
                <td>Found $count accounts with SPNs vulnerable to Kerberoasting. These accounts should use strong passwords and account rotation.</td>
            </tr>
"@
        } else {
            $findings += @"
            <tr class="secure">
                <td>Kerberoastable Accounts</td>
                <td><span style="color: green; font-weight: bold;">SECURE</span></td>
                <td>No vulnerable service accounts found.</td>
            </tr>
"@
        }
    }
    
    # ASREP Roastable accounts
    $asrepFile = Join-Path $OutputPath "ASREPRoastable_Users.csv"
    if (Test-Path $asrepFile) {
        $count = (Import-Csv $asrepFile | Measure-Object).Count
        if ($count -gt 0) {
            $findings += @"
            <tr class="critical">
                <td>ASREPRoastable Accounts</td>
                <td><span style="color: darkred; font-weight: bold;">CRITICAL RISK</span></td>
                <td>Found $count accounts with pre-authentication disabled. These accounts can be exploited without valid credentials.</td>
            </tr>
"@
        } else {
            $findings += @"
            <tr class="secure">
                <td>ASREPRoastable Accounts</td>
                <td><span style="color: green; font-weight: bold;">SECURE</span></td>
                <td>No accounts with Kerberos pre-authentication disabled. Good security posture.</td>
            </tr>
"@
        }
    }
    
    # Unconstrained Delegation
    $unDelegFile = Join-Path $OutputPath "Unconstrained_Delegation_Computers.csv"
    if (Test-Path $unDelegFile) {
        $count = (Import-Csv $unDelegFile | Measure-Object).Count
        if ($count -gt 0) {
            $findings += @"
            <tr class="critical">
                <td>Unconstrained Delegation</td>
                <td><span style="color: darkred; font-weight: bold;">CRITICAL RISK</span></td>
                <td>Found $count computers with unconstrained delegation enabled. These systems can be used for privilege escalation.</td>
            </tr>
"@
        } else {
            $findings += @"
            <tr class="secure">
                <td>Unconstrained Delegation</td>
                <td><span style="color: green; font-weight: bold;">SECURE</span></td>
                <td>No systems with unconstrained delegation. Good security posture.</td>
            </tr>
"@
        }
    }
    
    # SID History
    $sidHistoryFile = Join-Path $OutputPath "SIDHistory_Accounts.csv"
    if (Test-Path $sidHistoryFile) {
        $count = (Import-Csv $sidHistoryFile | Measure-Object).Count
        if ($count -gt 0) {
            $findings += @"
            <tr class="high">
                <td>SID History</td>
                <td><span style="color: red; font-weight: bold;">HIGH RISK</span></td>
                <td>Found $count accounts with SID History. These can be leveraged for privilege escalation.</td>
            </tr>
"@
        } else {
            $findings += @"
            <tr class="secure">
                <td>SID History</td>
                <td><span style="color: green; font-weight: bold;">SECURE</span></td>
                <td>No accounts with SID History found. Good security posture.</td>
            </tr>
"@
        }
    }
    
    # Password Policy
    $policyFile = Join-Path $OutputPath "Password_Policy_Summary.csv"
    if (Test-Path $policyFile) {
        $policy = Import-Csv $policyFile
        $policyRating = "SECURE"
        $policyColor = "green"
        $policyText = "Password policy meets best practices."
        
        if ($policy.MinPasswordLength -lt 14) {
            $policyRating = "MEDIUM RISK"
            $policyColor = "orange"
            $policyText = "Password policy below recommended standards (min length $($policy.MinPasswordLength) < 14)."
        }
        
        if ($policy.MinPasswordLength -lt 8) {
            $policyRating = "HIGH RISK"
            $policyColor = "red"
            $policyText = "Password policy is weak (min length $($policy.MinPasswordLength) < 8)."
        }
        
        if (-not $policy.ComplexityEnabled) {
            $policyRating = "HIGH RISK"
            $policyColor = "red"
            $policyText += " Complexity requirements disabled."
        }
        
        $findings += @"
            <tr class="$($policyRating.ToLower().Replace(' ', ''))">
                <td>Password Policy</td>
                <td><span style="color: $policyColor; font-weight: bold;">$policyRating</span></td>
                <td>$policyText Length: $($policy.MinPasswordLength), History: $($policy.PasswordHistoryCount), Complexity: $($policy.ComplexityEnabled)</td>
            </tr>
"@
    }
    
    # Old OS machines
    $oldOSFile = Join-Path $OutputPath "Old_OS_Machines.csv"
    if (Test-Path $oldOSFile) {
        $count = (Import-Csv $oldOSFile | Measure-Object).Count
        if ($count -gt 0) {
            $findings += @"
            <tr class="high">
                <td>Legacy Operating Systems</td>
                <td><span style="color: red; font-weight: bold;">HIGH RISK</span></td>
                <td>Found $count computers with outdated/unsupported operating systems. These systems lack security patches.</td>
            </tr>
"@
        } else {
            $findings += @"
            <tr class="secure">
                <td>Legacy Operating Systems</td>
                <td><span style="color: green; font-weight: bold;">SECURE</span></td>
                <td>No legacy operating systems detected. Good security posture.</td>
            </tr>
"@
        }
    }
    
    # Add findings to HTML report
    $htmlReport += $findings
    $htmlReport += @"
        </table>
    </div>

    <h2>Detailed Findings & Recommendations</h2>
"@

    # Add detailed findings with compliance mapping and remediation guidance
    $detailedFindings = @(
        @{
            Title = "Privileged Group Membership"
            Risk = "Medium"
            Files = @("Domain_Admins.csv", "Enterprise_Admins.csv", "Schema_Admins.csv")
            Compliance = "NIST 800-53: AC-6, AC-2; ISO 27001: A.9.2.3; CIS Controls: 4.3"
            Description = "Privileged groups like Domain Admins should have minimal membership. Each member should be reviewed regularly."
            Remediation = "Review all members of privileged groups. Remove unnecessary accounts. Implement a tiered administration model with separate admin accounts."
        },
        @{
            Title = "Kerberoastable Service Accounts"
            Risk = "High"
            Files = @("Kerberoastable_Users.csv")
            Compliance = "NIST 800-53: IA-2(8), AC-3; ISO 27001: A.9.4.2; CIS Controls: 4.4, 16.9"
            Description = "Service accounts with SPNs can be targeted for offline password cracking via Kerberoasting attacks."
            Remediation = "Use 25+ character complex passwords for all service accounts. Implement managed service accounts (gMSA) where possible. Review and remove unnecessary SPNs."
        },
        @{
            Title = "ASREPRoastable User Accounts"
            Risk = "Critical"
            Files = @("ASREPRoastable_Users.csv")
            Compliance = "NIST 800-53: IA-2, IA-5; ISO 27001: A.9.4.2; CIS Controls: 16"
            Description = "Accounts with Kerberos pre-authentication disabled can be exploited to obtain password hashes without authentication."
            Remediation = "Enable Kerberos pre-authentication for all accounts. Use the following PowerShell command: Get-ADUser -Identity 'USERNAME' | Set-ADUser -DoesNotRequirePreAuth $false"
        },
        @{
            Title = "SID History Abuse"
            Risk = "High"
            Files = @("SIDHistory_Accounts.csv")
            Compliance = "NIST 800-53: AC-2, AC-6; ISO 27001: A.9.2.2, A.9.2.6; CIS Controls: 16.9"
            Description = "SID History attribute can be exploited for privilege escalation through token manipulation."
            Remediation = "Review all accounts with SID History. Clear SIDHistory attribute when no longer needed for migrations. Monitor changes to SIDHistory attribute."
        },
        @{
            Title = "Unconstrained Delegation"
            Risk = "Critical"
            Files = @("Unconstrained_Delegation_Computers.csv", "Unconstrained_Delegation_Users.csv")
            Compliance = "NIST 800-53: AC-3, AC-6; ISO 27001: A.9.4.1; CIS Controls: 4.3, 4.8"
            Description = "Systems with unconstrained delegation can steal authentication tickets from connecting users, including domain administrators."
            Remediation = "Replace unconstrained delegation with constrained delegation where needed. Disable delegation for all other systems. Protect privileged accounts using 'Account is sensitive and cannot be delegated' option."
        },
        @{
            Title = "AdminSDHolder Protected Accounts"
            Risk = "Medium"
            Files = @("AdminSDHolder_Protected_Accounts.csv")
            Compliance = "NIST 800-53: AC-2, AC-6; ISO 27001: A.9.2.3; CIS Controls: 4.1, 4.8"
            Description = "Accounts protected by AdminSDHolder get privileges reapplied every hour. Can lead to unintended privilege persistence."
            Remediation = "Review all accounts with AdminCount=1. Remove accounts from protected groups if not needed. Check for lingering AdminCount attributes on accounts no longer in privileged groups."
        },
        @{
            Title = "Password Policy Assessment"
            Risk = "Medium" 
            Files = @("Password_Policy.txt", "Password_Policy_Summary.csv")
            Compliance = "NIST 800-53: IA-5; ISO 27001: A.9.4.3; CIS Controls: 16.2, 16.5"
            Description = "Password policies define authentication strength. Weak policies can lead to easily cracked passwords."
            Remediation = "Implement strong password policies: length 14+, complexity enabled, history 24+, max age 90 days or less. Consider implementing FGPP for different user types."
        },
        @{
            Title = "Legacy Operating Systems"
            Risk = "High"
            Files = @("Old_OS_Machines.csv")
            Compliance = "NIST 800-53: CM-2, CM-6; ISO 27001: A.12.6.1; CIS Controls: 2.2, 3.4"
            Description = "Legacy operating systems no longer receiving security updates pose significant risk to the environment."
            Remediation = "Upgrade or decommission legacy systems. If upgrading is not possible, implement network isolation through firewalls/VLANs."
        }
    )
    
    foreach ($finding in $detailedFindings) {
        $hasFindings = $false
        foreach ($file in $finding.Files) {
            if (Test-Path (Join-Path $OutputPath $file)) {
                $hasFindings = $true
                break
            }
        }
        
        if ($hasFindings) {
            $cssClass = $finding.Risk.ToLower()
            $htmlReport += @"
    <div class="finding $cssClass">
        <h3>$($finding.Title) - $($finding.Risk) Risk</h3>
        <p><strong>Compliance Mappings:</strong> $($finding.Compliance)</p>
        <p><strong>Description:</strong> $($finding.Description)</p>
        <p><strong>Remediation:</strong> $($finding.Remediation)</p>
        <p><strong>Related Files:</strong> $($finding.Files -join ", ")</p>
    </div>
"@
        }
    }
    
    # Close HTML file
    $htmlReport += @"
    <h2>Compliance Mapping Summary</h2>
    <table>
        <tr>
            <th>Framework</th>
            <th>Controls</th>
            <th>Relevance</th>
        </tr>
        <tr>
            <td>NIST 800-53</td>
            <td>AC-2, AC-3, AC-5, AC-6, IA-2, IA-5</td>
            <td>Federal systems compliance</td>
        </tr>
        <tr>
            <td>NIST 800-171</td>
            <td>3.1.1, 3.1.2, 3.1.5, 3.1.7, 3.5.2</td>
            <td>Defense contractors / CUI handling</td>
        </tr>
        <tr>
            <td>ISO 27001</td>
            <td>A.9.2.3, A.9.2.4, A.9.2.6, A.9.4.1, A.9.4.2, A.9.4.3</td>
            <td>International security standard</td>
        </tr>
        <tr>
            <td>CIS Controls</td>
            <td>4.1, 4.3, 4.8, 16.2, 16.9</td>
            <td>Security best practices</td>
        </tr>
    </table>

    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc;">
        <p>Generated on $reportDate | Format: HTML Report</p>
        <p>This report contains sensitive security information. Handle appropriately.</p>
    </div>
</body>
</html>
"@
    
    # Save HTML report
    $htmlReport | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "[+] HTML report generated: $reportPath"
    
    return $true
}

# Main function to run the audit
function Start-RemoteADAudit {
    $startTime = Get-Date
    Write-Host "[+] Starting Remote AD Audit for domain: $DomainName via $DomainController"
    Write-Host "[+] Start time: $startTime"
    Write-Host "[+] Output directory: $OutputPath"
    
    # Collection of module functions to run
    $moduleFunctions = @{
        "basic" = @{ Function = "Get-BasicDomainInfo"; Description = "Basic Domain Information" }
        "password" = @{ Function = "Get-PasswordPolicy"; Description = "Password Policy Assessment" }
        "privileged" = @{ Function = "Get-PrivilegedGroups"; Description = "Privileged Group Membership" }
        "kerberoast" = @{ Function = "Get-KerberoastableUsers"; Description = "Kerberoastable Service Accounts" }
        "asreproast" = @{ Function = "Get-ASREPRoastableUsers"; Description = "ASREPRoastable User Accounts" }
        "trusts" = @{ Function = "Get-DomainTrusts"; Description = "Domain Trust Relationships" }
        "disabled" = @{ Function = "Get-DisabledAndInactiveAccounts"; Description = "Disabled & Inactive Accounts" }
        "recent" = @{ Function = "Get-RecentChanges"; Description = "Recent Account/Group Changes" }
        "oldos" = @{ Function = "Get-OldOSMachines"; Description = "Legacy Operating Systems" }
        "adminsd" = @{ Function = "Get-AdminSDHolderProtectedAccounts"; Description = "AdminSDHolder Protected Accounts" }
        "sidhistory" = @{ Function = "Get-SIDHistoryAccounts"; Description = "SID History Risks" }
        "unconstrained" = @{ Function = "Get-UnconstrainedDelegation"; Description = "Unconstrained Delegation Risks" }
        "report" = @{ Function = "Generate-HTMLReport"; Description = "HTML Report Generation" }
    }
    
    # Connection test
    $connected = Test-DCConnection
    if (-not $connected) {
        Write-Warning "[-] Cannot connect to domain controller $DomainController. Audit aborted."
        return
    }
    
    # Run modules based on selection
    if ($Modules -contains "all") {
        Write-Host "[+] Running all audit modules..."
        foreach ($module in $moduleFunctions.Keys) {
            $func = $moduleFunctions[$module].Function
            $desc = $moduleFunctions[$module].Description
            
            Write-Host "`n[MODULE] $desc"
            & (Get-Item "Function:$func").ScriptBlock
        }
    } else {
        # Run selected modules
        foreach ($module in $Modules) {
            if ($moduleFunctions.ContainsKey($module)) {
                $func = $moduleFunctions[$module].Function
                $desc = $moduleFunctions[$module].Description
                
                Write-Host "`n[MODULE] $desc"
                & (Get-Item "Function:$func").ScriptBlock
            } else {
                Write-Warning "[-] Unknown module: $module"
            }
        }
    }
    
    # Always generate report unless specifically excluded
    if (-not ($Modules -contains "report") -and -not ($Modules -contains "all")) {
        Write-Host "`n[MODULE] HTML Report Generation"
        Generate-HTMLReport
    }
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalMinutes
    
    Write-Host "`n[+] AD Audit completed in $([math]::Round($duration, 2)) minutes"
    Write-Host "[+] Results saved to: $OutputPath"
    Write-Host "[+] HTML Report: $((Join-Path $OutputPath "AD_Audit_Report.html"))"
}

# Display help if requested
if ($Modules -contains "help" -or $Modules -contains "-help") {
    Write-Host @"
Remote-ADAudit.ps1 - Remote Active Directory Security Assessment

USAGE:
   .\Remote-ADAudit.ps1 -DomainController dc.domain.com -DomainName domain.com [-Credential `$cred] [-Modules module1,module2] [-OutputPath path]

PARAMETERS:
   -DomainController   Domain controller to query (required)
   -DomainName         Domain name (required)
   -Credential         PSCredential object for authentication (optional)
   -Modules            Modules to run (default: "all")
   -OutputPath         Output directory (default: .\ADAudit-Results)

AVAILABLE MODULES:
   all           Run all modules (default)
   basic         Basic domain information 
   password      Password policy assessment
   privileged    Privileged group membership
   kerberoast    Kerberoastable service accounts
   asreproast    ASREPRoastable user accounts
   trusts        Domain trust relationships
   disabled      Disabled and inactive accounts
   recent        Recent account/group changes
   oldos         Legacy operating systems
   adminsd       AdminSDHolder protected accounts
   sidhistory    SID History risks
   unconstrained Unconstrained delegation risks
   report        HTML report generation (always runs unless excluded)

EXAMPLES:
   .\Remote-ADAudit.ps1 -DomainController dc.contoso.com -DomainName contoso.com
   .\Remote-ADAudit.ps1 -DomainController 192.168.1.10 -DomainName contoso.local -Modules "password,privileged,kerberoast"
   `$cred = Get-Credential
   .\Remote-ADAudit.ps1 -DomainController dc.contoso.com -DomainName contoso.com -Credential `$cred -OutputPath "C:\Audit"
"@
    exit
}

# Start the audit
Start-RemoteADAudit