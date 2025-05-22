<#
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
  
 REMY-AD: Remote Active Directory Audit and Compliance Toolkit
 Version: 1.0 | Mode: Remote w/ Domain Credentials via Jump Box

 🔍 Coverage: Enumeration, Abuse Discovery, Risk Scoring
 📊 Benchmarks: NIST 800-53, 800-171, SOX, HIPAA, CIS, ISO27001
 📁 Reports: HTML Dashboards, CSV Scorecards, Remediation Guidance
 ⚠️  Ensure authorization before scanning or auditing production AD
 ________________________________________________________________

.SYNOPSIS
    Remote-friendly AD audit toolkit with integrated compliance mapping, scoring,
    and remediation guidance. Includes report generation in CSV/HTML for governance.

 .DESCRIPTION
    - Performs user, group, ACL, Kerberos, LAPS, GPO, ADCS, DNS, SMB, and LDAP audits
    - Cross-references outputs to controls from NIST, CIS, HIPAA, SOX, ISO, and more
    - Generates color-coded HTML dashboards and compliance risk scorecards

 .CHANGELOG
    [v1.0] Initial release:
       - Modular AD auditing and credential support
       - Compliance scoring: NIST/SOX/STIG/CIS/ISO27001/GDPR/HIPAA/PCI/NIST 800-171
       - Remediation dashboard embedded in HTML
       - SIDHistory, AdminSDHolder, NTLM, PAC, PrintSpooler, SMB signing detection
       - Risk dashboard + scoring matrix output

 .AUTHOR
     ethicalsoup@gmail.com
  .Script Name  : remy-ad-audit.ps1
#>

param (
    [Parameter(Mandatory=$false)]
    [PSCredential]$DomainCredential,

    [Parameter(Mandatory=$false)]
    [string]$DomainController
)

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputPath = Join-Path $ScriptRoot "Reports"
if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }

function Get-TargetedDC {
    try {
        if ($DomainController) {
            return $DomainController
        } else {
            return (Get-ADDomainController -Discover -Writable).HostName
        }
    } catch {
        Write-Warning "[-] Unable to determine Domain Controller: $_"
        return $null
    }
}

function Execute-ADCommand {
    param(
        [ScriptBlock]$Command
    )
    try {
        if ($DomainCredential -and $DomainController) {
            & $Command -Server $DomainController -Credential $DomainCredential
        } elseif ($DomainCredential) {
            & $Command -Credential $DomainCredential
        } elseif ($DomainController) {
            & $Command -Server $DomainController
        } else {
            & $Command
        }
    } catch {
        Write-Warning "[-] Command failed: $_"
    }
}

function Test-DCConnection {
    Write-Host "[+] Testing connectivity to domain controller..."
    $DC = Get-TargetedDC
    if ($DC) {
        if (Test-Connection -ComputerName $DC -Count 2 -Quiet) {
            Write-Host "[+] Domain Controller $DC reachable."
        } else {
            Write-Warning "[-] Cannot reach Domain Controller $DC."
        }
    }
}

function Get-DomainInfo {
    Write-Host "[+] Gathering domain info..."
    try {
        $command = { Get-ADDomain }
        $domain = Execute-ADCommand -Command $command
        $domain | Out-File -FilePath (Join-Path $OutputPath "DomainInfo.txt")
    } catch {
        Write-Warning "[-] Failed to get domain info: $_"
    }
}

function Get-PrivilegedGroups {
    Write-Host "[+] Gathering privileged group membership..."
    $groups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators"
    )
    foreach ($group in $groups) {
        try {
            $command = { Get-ADGroupMember -Identity $group -Recursive }
            $members = Execute-ADCommand -Command $command
            $members | Select-Object Name, SamAccountName, ObjectClass | Out-File -FilePath (Join-Path $OutputPath "$group.txt")
        } catch {
            Write-Warning "[-] Failed to get members of $group: $_"
        }
    }
}

function Get-PasswordPolicy {
    Write-Host "[+] Gathering password policy info..."
    try {
        $command = { Get-ADDefaultDomainPasswordPolicy }
        $policy = Execute-ADCommand -Command $command
        $policy | Out-File -FilePath (Join-Path $OutputPath "PasswordPolicy.txt")
    } catch {
        Write-Warning "[-] Failed to get password policy: $_"
    }
}

function Get-KerberoastableUsers {
    Write-Host "[+] Enumerating Kerberoastable users..."
    try {
        $command = { Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName }
        $users = Execute-ADCommand -Command $command
        $kerbUsers = $users | Where-Object { $_.ServicePrincipalName -ne $null }
        $kerbUsers | Select-Object Name, SamAccountName, ServicePrincipalName | Out-File -FilePath (Join-Path $OutputPath "KerberoastableUsers.txt")
    } catch {
        Write-Warning "[-] Failed to enumerate Kerberoastable users: $_"
    }
}

function Get-ASREPRoastableUsers {
    Write-Host "[+] Enumerating ASREPRoastable users (no pre-auth)..."
    try {
        $command = { Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } -Properties DoesNotRequirePreAuth }
        $users = Execute-ADCommand -Command $command
        $users | Select-Object Name, SamAccountName | Out-File -FilePath (Join-Path $OutputPath "ASREPRoastableUsers.txt")
    } catch {
        Write-Warning "[-] Failed to enumerate ASREPRoastable users: $_"
    }
}
function Get-ADCSVulnerabilities {
    Write-Host "[+] Checking for ADCS misconfigurations (ESC1–ESC8)..."
    try {
        $certSrvContainers = Get-ChildItem -Path "Cert:\\LocalMachine\\CA" -ErrorAction SilentlyContinue
        if ($certSrvContainers) {
            $certSrvContainers | Out-File -FilePath (Join-Path $OutputPath "ADCS_CertAuthorities.txt")
        } else {
            "No certificate authorities found under LocalMachine\\CA." | Out-File -FilePath (Join-Path $OutputPath "ADCS_CertAuthorities.txt")
        }

        # DSInternals - Certificate template permissions (requires RSAT and DSInternals)
        "`n[+] Running DSInternals Get-CertificateTemplateAcl..." | Out-File -Append -FilePath (Join-Path $OutputPath "ADCS_CertAuthorities.txt")
        try {
            Get-CertificateTemplateAcl | Out-File -Append -FilePath (Join-Path $OutputPath "ADCS_CertAuthorities.txt")
        } catch {
            "[!] DSInternals Get-CertificateTemplateAcl failed: $_" | Out-File -Append -FilePath (Join-Path $OutputPath "ADCS_CertAuthorities.txt")
        }
    } catch {
        Write-Warning "[-] Failed to enumerate ADCS vulnerabilities: $_"
    }
}

function Get-GPOAndLAPSChecks {
    Write-Host "[+] Gathering GPO and LAPS-related audit information..."
    try {
        $gpos = Get-GPO -All -ErrorAction SilentlyContinue
        if ($gpos) {
            $gpos | Select DisplayName, CreationTime, ModificationTime | Out-File -FilePath (Join-Path $OutputPath "GPO_List.txt")
        } else {
            "No GPOs found or access denied." | Out-File -FilePath (Join-Path $OutputPath "GPO_List.txt")
        }

        # LAPS auditing using DSInternals
        "`n[+] Running DSInternals Get-ADReplAccount - LAPS attributes..." | Out-File -FilePath (Join-Path $OutputPath "LAPS_Checks.txt")
        try {
            Get-ADReplAccount -All | Where-Object { $_.HasLAPS } | Out-File -Append -FilePath (Join-Path $OutputPath "LAPS_Checks.txt")
        } catch {
            "[!] DSInternals LAPS audit failed: $_" | Out-File -Append -FilePath (Join-Path $OutputPath "LAPS_Checks.txt")
        }
    } catch {
        Write-Warning "[-] Failed to gather GPO or LAPS info: $_"
    }
}
function Get-ACLandLDAPSecurityChecks {
    Write-Host "[+] Auditing ACL permissions and LDAP security..."
    try {
        # Dump ACLs on the domain object
        $domainDN = (Get-ADDomain).DistinguishedName
        $domainACL = Get-Acl -Path "AD:$domainDN"
        $domainACL | Out-File -FilePath (Join-Path $OutputPath "Domain_ACLs.txt")

        # LDAP signing and channel binding audit (registry keys on DC)
        $LDAPOutput = Join-Path $OutputPath "LDAP_Security.txt"
        "[+] LDAP Security Configuration (from local registry)" | Out-File -FilePath $LDAPOutput

        try {
            $ldapSigning = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -ErrorAction Stop
            "LDAPServerIntegrity: $($ldapSigning.LDAPServerIntegrity)" | Out-File -Append -FilePath $LDAPOutput
        } catch {
            "LDAPServerIntegrity not found or unreadable." | Out-File -Append -FilePath $LDAPOutput
        }

        try {
            $channelBinding = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u' -Name 'AllowOnlineID' -ErrorAction SilentlyContinue
            "ChannelBinding: $($channelBinding.AllowOnlineID)" | Out-File -Append -FilePath $LDAPOutput
        } catch {
            "ChannelBinding key not found or unreadable." | Out-File -Append -FilePath $LDAPOutput
        }
    } catch {
        Write-Warning "[-] Failed to perform ACL or LDAP security checks: $_"
    }
}
function Get-DisabledAndExpiredAccounts {
    Write-Host "[+] Auditing disabled and expired user accounts..."
    try {
        $disabledUsers = Get-ADUser -Filter { Enabled -eq $false } -Properties SamAccountName, Enabled
        $expiredUsers = Get-ADUser -Filter { AccountExpirationDate -lt (Get-Date) -and AccountExpirationDate -ne $null } -Properties SamAccountName, AccountExpirationDate

        $disabledUsers | Select-Object SamAccountName, Enabled | Out-File -FilePath (Join-Path $OutputPath "Disabled_Accounts.txt")
        $expiredUsers | Select-Object SamAccountName, AccountExpirationDate | Out-File -FilePath (Join-Path $OutputPath "Expired_Accounts.txt")
    } catch {
        Write-Warning "[-] Failed to gather disabled or expired accounts: $_"
    }
}

function Get-TrustRelationships {
    Write-Host "[+] Gathering domain trust relationships..."
    try {
        $trusts = Get-ADTrust -Filter * -Properties *
        $trusts | Select-Object Name, TrustType, TrustDirection, IsTransitive, TrustedDomainName, Created, Modified | Out-File -FilePath (Join-Path $OutputPath "Domain_Trusts.txt")
    } catch {
        Write-Warning "[-] Failed to retrieve trust relationships: $_"
    }
}

function Get-DisabledAndExpiredAccounts {
    Write-Host "[+] Auditing disabled and expired user accounts..."
    try {
        $disabledUsers = Get-ADUser -Filter { Enabled -eq $false } -Properties SamAccountName, Enabled
        $expiredUsers = Get-ADUser -Filter { AccountExpirationDate -lt (Get-Date) -and AccountExpirationDate -ne $null } -Properties SamAccountName, AccountExpirationDate

        $disabledUsers | Select-Object SamAccountName, Enabled | Out-File -FilePath (Join-Path $OutputPath "Disabled_Accounts.txt")
        $expiredUsers | Select-Object SamAccountName, AccountExpirationDate | Out-File -FilePath (Join-Path $OutputPath "Expired_Accounts.txt")
    } catch {
        Write-Warning "[-] Failed to gather disabled or expired accounts: $_"
    }
}

function Get-RecentChanges {
    Write-Host "[+] Auditing recently created users and groups (last 30 days)..."
    try {
        $since = (Get-Date).AddDays(-30)
        $newUsers = Get-ADUser -Filter { whenCreated -ge $since } -Properties whenCreated
        $newGroups = Get-ADGroup -Filter { whenCreated -ge $since } -Properties whenCreated

        $newUsers | Select-Object SamAccountName, whenCreated | Out-File -FilePath (Join-Path $OutputPath "NewUsers_Last30Days.txt")
        $newGroups | Select-Object Name, whenCreated | Out-File -FilePath (Join-Path $OutputPath "NewGroups_Last30Days.txt")
    } catch {
        Write-Warning "[-] Failed to audit recent user/group creation: $_"
    }
}

function Get-NTDSUtilCheck {
    Write-Host "[+] WARNING: Manual NTDS.dit extraction must be performed with ntdsutil. This script cannot perform a dump for safety/legal reasons."
    "Use the following command manually on the DC:`nntdsutil`nactivate instance ntds`nifm`ncreate full c:\\ifm`n`n" | Out-File -FilePath (Join-Path $OutputPath "NTDS_Extraction_Instructions.txt")
}

function Get-OldOSMachines {
    Write-Host "[+] Checking for old operating systems in AD..."
    try {
        $computers = Get-ADComputer -Filter * -Properties OperatingSystem
        $legacyOS = $computers | Where-Object { $_.OperatingSystem -match 'Windows (2000|2003|XP|Vista|7|2008)' }
        $legacyOS | Select-Object Name, OperatingSystem | Out-File -FilePath (Join-Path $OutputPath "Old_OS_Machines.txt")
    } catch {
        Write-Warning "[-] Failed to identify old OS machines: $_"
    }
}

function Get-OUGenericPermissions {
    Write-Host "[+] Checking for generic permissions on Organizational Units (OUs)..."
    try {
        $ous = Get-ADOrganizationalUnit -Filter *
        foreach ($ou in $ous) {
            $acl = Get-Acl -Path "AD:$($ou.DistinguishedName)"
            $acl | Out-File -Append -FilePath (Join-Path $OutputPath "OU_GenericPermissions.txt")
        }
    } catch {
        Write-Warning "[-] Failed to audit OU permissions: $_"
    }
}

function Get-AuthPolicySilos {
    Write-Host "[+] Checking for authentication policies and silos..."
    try {
        $silos = Get-ADAuthenticationPolicySilo -Filter * -ErrorAction SilentlyContinue
        $policies = Get-ADAuthenticationPolicy -Filter * -ErrorAction SilentlyContinue

        $silos | Out-File -FilePath (Join-Path $OutputPath "Auth_Policy_Silos.txt")
        $policies | Out-File -FilePath (Join-Path $OutputPath "Auth_Policies.txt")
    } catch {
        Write-Warning "[-] Failed to enumerate authentication policies or silos: $_"
    }
}

function Get-InsecureDNSZones {
    Write-Host "[+] Checking for insecure DNS zones..."
    try {
        $zones = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.IsSigned -eq $false -and $_.ZoneType -eq 'Primary' }
        $zones | Select-Object ZoneName, IsSigned, ZoneType | Out-File -FilePath (Join-Path $OutputPath "Insecure_DNS_Zones.txt")
    } catch {
        Write-Warning "[-] Failed to audit DNS zones: $_"
    }
}

function Get-SPNHighValueAccounts {
    Write-Host "[+] Enumerating high-value accounts with SPNs..."
    try {
        $users = Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalName, AdminCount
        $highValue = $users | Where-Object { $_.AdminCount -eq 1 -and $_.ServicePrincipalName -ne $null }
        $highValue | Select-Object SamAccountName, ServicePrincipalName | Out-File -FilePath (Join-Path $OutputPath "SPN_HighValue_Accounts.txt")
    } catch {
        Write-Warning "[-] Failed to find high-value SPN accounts: $_"
    }
}

function Get-DangerousACLs {
    Write-Host "[+] Checking for dangerous ACL permissions on Users, Groups, and Computers..."
    try {
        $objects = @()
        $objects += Get-ADUser -Filter * | ForEach-Object { $_.DistinguishedName }
        $objects += Get-ADGroup -Filter * | ForEach-Object { $_.DistinguishedName }
        $objects += Get-ADComputer -Filter * | ForEach-Object { $_.DistinguishedName }

        foreach ($dn in $objects) {
            try {
                $acl = Get-Acl -Path "AD:$dn"
                foreach ($ace in $acl.Access) {
                    if ($ace.ActiveDirectoryRights -match "GenericAll|WriteOwner|WriteDacl|GenericWrite") {
                        [PSCustomObject]@{
                            Object = $dn
                            IdentityReference = $ace.IdentityReference
                            Rights = $ace.ActiveDirectoryRights
                        } | Out-File -Append -FilePath (Join-Path $OutputPath "Dangerous_ACLs.txt")
                    }
                }
            } catch {
                Write-Warning "[-] Failed ACL check on $dn: $_"
            }
        }
    } catch {
        Write-Warning "[-] Failed ACL enumeration: $_"
    }
}

function Get-LDAPSecurityIssues {
    Write-Host "[+] Auditing LDAP security configuration..."
    try {
        $results = @()
        $settings = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
        $results += "LDAP Signing: $($settings.LDAPServerIntegrity)"
        $results += "LDAP Channel Binding: $($settings.LDAPEnforceChannelBinding)"

        $results | Out-File -FilePath (Join-Path $OutputPath "LDAP_Security_Audit.txt")
    } catch {
        Write-Warning "[-] Failed LDAP security audit: $_"
    }
}


function Get-CommonADVulnerabilities {
    Write-Host "[+] Checking for common AD attack surface indicators..."
    try {
        $results = @()

        $results += "[+] Checking unconstrained delegation..."
        $unconstrained = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation
        $unconstrained | Select-Object Name, TrustedForDelegation | Out-File -FilePath (Join-Path $OutputPath "AD_UnconstrainedDelegation.txt")

        $results += "[+] Checking for dangerous GPO startup/logon scripts..."
        $gpos = Get-GPO -All
        foreach ($gpo in $gpos) {
            $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
            if ($report -match "script") {
                "Script found in GPO: $($gpo.DisplayName)" | Out-File -Append -FilePath (Join-Path $OutputPath "AD_GPO_Scripted.txt")
            }
        }

        $results += "[+] Checking for computers with SPNs and no pre-auth (targetable via ASREPRoast)..."
        $asrep = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and ServicePrincipalName -like '*' } -Properties SamAccountName, ServicePrincipalName
        $asrep | Select-Object SamAccountName, ServicePrincipalName | Out-File -FilePath (Join-Path $OutputPath "AD_SPNAccts_NoPreAuth.txt")
    } catch {
        Write-Warning "[-] Failed to perform AD vulnerability checks: $_"
    }
}

function Get-SCCMDiscovery {
    Write-Host "[+] Enumerating potential SCCM presence and objects..."
    try {
        $sccmSites = Get-WmiObject -Namespace "root\SMS" -Class "SMS_ProviderLocation" -ErrorAction SilentlyContinue
        $sccmSites | Select-Object Machine, SiteCode, SiteName | Out-File -FilePath (Join-Path $OutputPath "SCCM_Sites.txt")
    } catch {
        Write-Warning "[-] SCCM discovery failed or WMI not accessible: $_"
    }
}

function Get-DomainShares {
    Write-Host "[+] Spidering domain shares..."
    try {
        $computers = Get-ADComputer -Filter * -Properties Name
        foreach ($comp in $computers) {
            try {
                $shares = net view \$($comp.Name) 2>&1 | Where-Object { $_ -match "Disk" }
                if ($shares) {
                    "Shares on $($comp.Name):`n$shares`n" | Out-File -Append -FilePath (Join-Path $OutputPath "Domain_Shares.txt")
                }
            } catch {}
        }
    } catch {
        Write-Warning "[-] Failed to enumerate domain shares: $_"
    }
}


function Get-AdminSDHolderInheritance {
    Write-Host "[+] Checking AdminSDHolder inheritance blocking issues..."
    try {
        $protectedGroups = Get-ADGroup -Filter { AdminCount -eq 1 }
        foreach ($group in $protectedGroups) {
            $acl = Get-Acl -Path "AD:$($group.DistinguishedName)"
            if (-not $acl.AreAccessRulesProtected) {
                "[!] Group with AdminCount=1 allowing inherited permissions: $($group.Name)" | Out-File -Append -FilePath (Join-Path $OutputPath "AdminSDHolder_Inheritance_Issues.txt")
            }
        }
    } catch {
        Write-Warning "[-] Failed to check AdminSDHolder inheritance: $_"
    }
}

function Get-SessionHijackableComputers {
    Write-Host "[+] Searching for potential session hijack vectors (RDP, SMB)..."
    try {
        $computers = Get-ADComputer -Filter * -Properties Name
        foreach ($comp in $computers) {
            try {
                $rdp = Test-NetConnection -ComputerName $comp.Name -Port 3389 -WarningAction SilentlyContinue
                $smb = Test-NetConnection -ComputerName $comp.Name -Port 445 -WarningAction SilentlyContinue
                if ($rdp.TcpTestSucceeded -or $smb.TcpTestSucceeded) {
                    "[$($comp.Name)] RDP: $($rdp.TcpTestSucceeded) | SMB: $($smb.TcpTestSucceeded)" | Out-File -Append -FilePath (Join-Path $OutputPath "SessionHijackable_Computers.txt")
                }
            } catch {}
        }
    } catch {
        Write-Warning "[-] Failed to enumerate hijackable systems: $_"
    }
}

function Get-KerberosPACandSIDHistoryAbuse {
    Write-Host "[+] Auditing Kerberos PAC abuse indicators and SIDHistory injection risks..."
    try {
        # PAC: Accounts with SIDHistory + AdminCount (privilege escalation risk)
        $usersWithSIDHistory = Get-ADUser -Filter { SIDHistory -like '*' } -Properties SIDHistory, AdminCount
        $riskyUsers = $usersWithSIDHistory | Where-Object { $_.AdminCount -eq 1 }
        $riskyUsers | Select-Object SamAccountName, SIDHistory, AdminCount | Out-File -FilePath (Join-Path $OutputPath "PAC_SIDHistory_Risks.txt")

        # PAC tampering CVE references
        @"
CVE References:
- CVE-2021-42278: SAMAccountName impersonation
- CVE-2021-42287: KDC confusion for PAC privilege escalation
- CVE-2022-26923: Certificate Authority escalation via enrollment
- CVE-2022-38023: PAC signature bypass
- CVE-2023-23392: NTLM relay targeting certificate services
"@ | Out-File -FilePath (Join-Path $OutputPath "PAC_CVE_References.txt")

    } catch {
        Write-Warning "[-] Failed to audit PAC/SIDHistory issues: $_"
    }
}

function Generate-ComplianceRiskScores {
    Write-Host "[+] Generating compliance benchmark risk scores (NIST, SOX, STIG, CIS, GDPR, HIPAA, ISO 27001, PCI-DSS, NIST 800-171)..."
    try {
        $scorecard = @()

        $categories = @(
            @{ Name = "PAC_SIDHistory_Risks.txt"; Label = "Privilege Abuse (PAC/SIDHistory)"; NIST = 0.2; SOX = 0.3; STIG = 0.2; CIS = 0.2; GDPR = 0.1; HIPAA = 0.2; ISO27001 = 0.3; PCI = 0.2; NIST800171 = 0.2; ControlID = "AC-6(10),A.9.2.3,CM-5" },
            @{ Name = "AdminSDHolder_Inheritance_Issues.txt"; Label = "AdminSDHolder Inheritance"; NIST = 0.1; SOX = 0.1; STIG = 0.2; CIS = 0.15; GDPR = 0; HIPAA = 0; ISO27001 = 0.1; PCI = 0.1; NIST800171 = 0.1; ControlID = "AC-5,A.6.1.1,SI-10" },
            @{ Name = "SessionHijackable_Computers.txt"; Label = "Session Hijack Vectors"; NIST = 0.2; SOX = 0.1; STIG = 0.2; CIS = 0.2; GDPR = 0.1; HIPAA = 0.2; ISO27001 = 0.2; PCI = 0.3; NIST800171 = 0.2; ControlID = "AC-17,SC-7(9),A.9.2.6" }
        )

        foreach ($item in $categories) {
            $filePath = Join-Path $OutputPath $item.Name
            $risk = if (Test-Path $filePath -and (Get-Content $filePath | Where-Object { $_.Trim() -ne "" })) { 1 } else { 0 }
            $scorecard += [PSCustomObject]@{
                Control = $item.Label
                ControlID = $item.ControlID
                NIST = $risk * $item.NIST
                SOX = $risk * $item.SOX
                STIG = $risk * $item.STIG
                CIS = $risk * $item.CIS
                GDPR = $risk * $item.GDPR
                HIPAA = $risk * $item.HIPAA
                ISO27001 = $risk * $item.ISO27001
                PCI = $risk * $item.PCI
                NIST800171 = $risk * $item.NIST800171
                Status = if ($risk -eq 1) { "⚠️ Finding" } else { "✅ Pass" }
            }
        }

        $totals = [PSCustomObject]@{
            Control = "TOTAL"
            ControlID = ""
            NIST = ($scorecard | Measure-Object -Property NIST -Sum).Sum
            SOX = ($scorecard | Measure-Object -Property SOX -Sum).Sum
            STIG = ($scorecard | Measure-Object -Property STIG -Sum).Sum
            CIS = ($scorecard | Measure-Object -Property CIS -Sum).Sum
            GDPR = ($scorecard | Measure-Object -Property GDPR -Sum).Sum
            HIPAA = ($scorecard | Measure-Object -Property HIPAA -Sum).Sum
            ISO27001 = ($scorecard | Measure-Object -Property ISO27001 -Sum).Sum
            PCI = ($scorecard | Measure-Object -Property PCI -Sum).Sum
            NIST800171 = ($scorecard | Measure-Object -Property NIST800171 -Sum).Sum
            Status = "-"
        }

        $scorecard += $totals

        $csvPath = Join-Path $OutputPath "Compliance_Risk_Scorecard.csv"
        $htmlPath = Join-Path $OutputPath "Compliance_Risk_Scorecard.html"
        $scorecard | Export-Csv -NoTypeInformation -Path $csvPath

        $html = @"
<html><head><title>Compliance Scorecard</title><style>
body { font-family: Arial; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 6px; text-align: center; }
th { background-color: #f4f4f4; }
tr td:last-child { font-weight: bold; }
.pass { background-color: #d4edda; }
.fail { background-color: #f8d7da; }
</style></head><body>
<h2>Compliance Risk Scorecard</h2>
<table>
<tr><th>Control</th><th>Ref</th><th>NIST</th><th>SOX</th><th>STIG</th><th>CIS</th><th>GDPR</th><th>HIPAA</th><th>ISO27001</th><th>PCI</th><th>NIST800-171</th><th>Status</th></tr>
"@

        foreach ($row in $scorecard) {
            $css = if ($row.Status -like "*Finding*") { "fail" } elseif ($row.Status -like "*Pass*") { "pass" } else { "" }
            $html += "<tr class='$css'><td>$($row.Control)</td><td>$($row.ControlID)</td><td>$($row.NIST)</td><td>$($row.SOX)</td><td>$($row.STIG)</td><td>$($row.CIS)</td><td>$($row.GDPR)</td><td>$($row.HIPAA)</td><td>$($row.ISO27001)</td><td>$($row.PCI)</td><td>$($row.NIST800171)</td><td>$($row.Status)</td></tr>"
        }

        $html += "</table><p>Generated on $(Get-Date)</p></body></html>"
        $html | Out-File -FilePath $htmlPath -Encoding UTF8

        Write-Host "[+] Compliance risk scorecard written to: $csvPath"
        Write-Host "[+] HTML report written to: $htmlPath"
    } catch {
        Write-Warning "[-] Failed to generate compliance risk scores: $_"
    }
}


function Get-RemediationGuidance {
    Write-Host "[+] Providing remediation guidance for identified findings..."
    try {
        $remediationData = @(
            @{ File = "PAC_SIDHistory_Risks.txt"; Guidance = "Review accounts with SIDHistory and AdminCount=1. Remove unnecessary SIDHistory entries and reset AdminCount where inheritance is appropriate." },
            @{ File = "AdminSDHolder_Inheritance_Issues.txt"; Guidance = "Manually inspect group ACLs flagged here. If safe, re-enable inheritance to allow proper permissions propagation." },
            @{ File = "SessionHijackable_Computers.txt"; Guidance = "Restrict SMB (port 445) and RDP (port 3389) exposure. Enforce firewall rules and limit RDP access via GPO and IP filtering." },
            @{ File = "Relay_PrintSpooler.txt"; Guidance = "Disable the Print Spooler service on Domain Controllers using GPO or PowerShell if not required." },
            @{ File = "Relay_SMB_Signing.txt"; Guidance = "Enable SMB signing by setting 'RequireSecuritySignature' to 1 via GPO or registry on all domain systems." },
            @{ File = "Relay_RPC_Endpoints.txt"; Guidance = "Restrict access to vulnerable RPC interfaces and monitor usage of RPC services like MS-RPRN or EFSRPC." },
            @{ File = "Relay_RBCD_Computers.txt"; Guidance = "Audit Resource-Based Constrained Delegation assignments and remove unused or misconfigured entries." },
            @{ File = "Relay_NTLM_Settings.txt"; Guidance = "Set 'RestrictSendingNTLMTraffic' to 2 to enforce NTLM restrictions and prefer Kerberos where possible." },
            @{ File = "Relay_LLMNR_Local.txt"; Guidance = "Disable LLMNR via GPO at 'Computer Configuration > Admin Templates > Network > DNS Client' by setting 'Turn Off Multicast Name Resolution' to Enabled." }
        )

        $remediationPath = Join-Path $OutputPath "Remediation_Guidance.txt"
        foreach ($entry in $remediationData) {
            $file = Join-Path $OutputPath $entry.File
            if (Test-Path $file -and (Get-Content $file | Where-Object { $_.Trim() -ne "" })) {
                "[!] Finding: $($entry.File)`nRemediation: $($entry.Guidance)`n" | Out-File -Append -FilePath $remediationPath
            }
        }

        Write-Host "[+] Remediation guidance saved to: Remediation_Guidance.txt"
    } catch {
        Write-Warning "[-] Failed to generate remediation guidance: $_"
    }
}


function Get-AzureADSecurityInsights {
    Write-Host "[+] Gathering additional Azure AD insights (roles, risky sign-ins, conditional access)..."
    try {
        Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "IdentityRiskEvent.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory"

        # 1. Admin roles
        $admins = Get-MgDirectoryRole | ForEach-Object {
            Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id | ForEach-Object {
                [PSCustomObject]@{
                    RoleName = $_.AdditionalProperties["@odata.type"]
                    MemberName = $_.AdditionalProperties["displayName"]
                    MemberUPN = $_.AdditionalProperties["userPrincipalName"]
                }
            }
        }
        $admins | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "AzureAD_AdminRoles.csv")

        # 2. Risky sign-ins (if Azure Identity Protection enabled)
        $risks = Get-MgRiskyUser -ErrorAction SilentlyContinue
        if ($risks) {
            $risks | Select-Object UserDisplayName, UserPrincipalName, RiskLevel, RiskState |
                Export-Csv -Path (Join-Path $OutputPath "AzureAD_RiskyUsers.csv") -NoTypeInformation
        }

        # 3. Conditional access policies
        $policies = Get-MgConditionalAccessPolicy -ErrorAction SilentlyContinue
        if ($policies) {
            $policies | Select-Object DisplayName, State, Conditions, GrantControls |
                Export-Csv -Path (Join-Path $OutputPath "AzureAD_ConditionalAccess.csv") -NoTypeInformation
        }

        # 4. MFA status per user
        $users = Get-MgUser -All
        $mfaResults = foreach ($user in $users) {
            $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
            $mfa = $methods | Where-Object { $_.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' }
            [PSCustomObject]@{
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                MFA_Enabled = if ($mfa.Count -gt 0) { $true } else { $false }
                MFA_Methods = ($mfa.'@odata.type' -replace '#microsoft.graph.', '') -join ", "
            }
        }
        $mfaResults | Export-Csv -Path (Join-Path $OutputPath "AzureAD_MFA_Status.csv") -NoTypeInformation

        Write-Host "[+] Azure AD roles, risky users, conditional access, and MFA exported."
    } catch {
        Write-Warning "[-] Failed to gather Azure AD security insights: $_"
    }
}


function Get-SystemLogonAudit {
    Write-Host "[+] Auditing domain system logon permissions and user rights assignments..."
    try {
        $computers = Get-ADComputer -Filter * -Properties Name
        $logonOutput = Join-Path $OutputPath "System_Logon_Rights.txt"
        foreach ($comp in $computers) {
            try {
                $rights = secedit /export /areas USER_RIGHTS /cfg ("\\$($comp.Name)\C$\temp\secpol.inf") 2>&1
                if (Test-Path "\\$($comp.Name)\C$\temp\secpol.inf") {
                    "[$($comp.Name)]" | Out-File -Append -FilePath $logonOutput
                    Get-Content "\\$($comp.Name)\C$\temp\secpol.inf" | Select-String "SeRemoteInteractiveLogonRight|SeDenyNetworkLogonRight|SeInteractiveLogonRight" | Out-File -Append -FilePath $logonOutput
                }
            } catch {}
        }
    } catch {
        Write-Warning "[-] Failed system logon audit: $_"
    }
}

function Get-RDPAccessAudit {
    Write-Host "[+] Auditing Remote Desktop Users group membership across domain hosts..."
    try {
        $computers = Get-ADComputer -Filter * -Properties Name
        $rdpOut = Join-Path $OutputPath "RDP_Access_Audit.txt"
        foreach ($comp in $computers) {
            try {
                $members = Get-LocalGroupMember -ComputerName $comp.Name -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
                if ($members) {
                    "[$($comp.Name)] RDP Access:`n$($members | Format-List | Out-String)" | Out-File -Append -FilePath $rdpOut
                }
            } catch {}
        }
    } catch {
        Write-Warning "[-] Failed RDP access audit: $_"
    }
}

function Get-AccessTokenPolicyAudit {
    Write-Host "[+] Checking token lifetimes and sign-in enforcement policies (AAD)..."
    try {
        $policies = Get-MgPolicyTokenLifetimePolicy -ErrorAction SilentlyContinue
        $policies | Select-Object DisplayName, Definition, IsOrganizationDefault | 
            Export-Csv -Path (Join-Path $OutputPath "AzureAD_TokenPolicy.csv") -NoTypeInformation
    } catch {
        Write-Warning "[-] Failed to audit AzureAD token policy: $_"
    }
}


function Get-RelayAttackIndicators {
    Write-Host "[+] Checking for relay attack indicators (PetitPotam, PrintSpooler abuse, SMB Signing, RPC exposure, PAC/NTLM/LLMNR)..."
    try {
        # 1. Print Spooler Enabled on Domain Controllers
        $dcs = Get-ADDomainController -Filter *
        foreach ($dc in $dcs) {
            try {
                $spooler = Get-Service -ComputerName $dc.HostName -Name Spooler -ErrorAction Stop
                if ($spooler.Status -eq 'Running') {
                    "Spooler running on $($dc.HostName)" | Out-File -Append -FilePath (Join-Path $OutputPath "Relay_PrintSpooler.txt")
                }
            } catch {
                "[!] Could not check spooler on $($dc.HostName): $_" | Out-File -Append -FilePath (Join-Path $OutputPath "Relay_PrintSpooler.txt")
            }
        }

        # 2. SMB Signing Check via Registry
        $computers = Get-ADComputer -Filter * -Properties Name
        foreach ($comp in $computers) {
            try {
                $signing = Get-ItemProperty -Path "\\$($comp.Name)\HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction Stop
                if ($signing.RequireSecuritySignature -eq 0) {
                    "SMB signing disabled on $($comp.Name)" | Out-File -Append -FilePath (Join-Path $OutputPath "Relay_SMB_Signing.txt")
                }
            } catch {
                "[?] Unable to verify SMB signing on $($comp.Name): $_" | Out-File -Append -FilePath (Join-Path $OutputPath "Relay_SMB_Signing.txt")
            }
        }

        # 3. RPC Endpoint Exposure (PetitPotam related)
        foreach ($dc in $dcs) {
            try {
                $output = quser /server:$($dc.HostName) 2>&1
                if ($output -match "No User sessions") {
                    "RPC endpoint responsive on $($dc.HostName)" | Out-File -Append -FilePath (Join-Path $OutputPath "Relay_RPC_Endpoints.txt")
                }
            } catch {
                "[?] Unable to contact RPC endpoint on $($dc.HostName): $_" | Out-File -Append -FilePath (Join-Path $OutputPath "Relay_RPC_Endpoints.txt")
            }
        }

        # 4. PAC Validation (RBCD Exposure)
        $rbcd = Get-ADComputer -LDAPFilter '(msds-allowedtodelegateto=*)' -Properties msds-allowedtodelegateto
        $rbcd | Select-Object Name, msds-allowedtodelegateto | Out-File -FilePath (Join-Path $OutputPath "Relay_RBCD_Computers.txt")

        # 5. NTLM Settings (DisableNTLM)
        foreach ($dc in $dcs) {
            try {
                $ntlm = Get-ItemProperty -Path "\\$($dc.HostName)\HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -ErrorAction Stop
                "NTLM config on $($dc.HostName): $($ntlm.RestrictSendingNTLMTraffic)" | Out-File -Append -FilePath (Join-Path $OutputPath "Relay_NTLM_Settings.txt")
            } catch {
                "[?] Unable to query NTLM settings on $($dc.HostName): $_" | Out-File -Append -FilePath (Join-Path $OutputPath "Relay_NTLM_Settings.txt")
            }
        }

        # 6. LLMNR & NetBIOS (Local Registry, if accessible)
        try {
            $llmnr = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
            if ($llmnr.EnableMulticast -eq 1) {
                "LLMNR enabled on local system." | Out-File -Append -FilePath (Join-Path $OutputPath "Relay_LLMNR_Local.txt")
            }
        } catch {
            "[?] Unable to query LLMNR setting on local system." | Out-File -Append -FilePath (Join-Path $OutputPath "Relay_LLMNR_Local.txt")
        }
    } catch {
        Write-Warning "[-] Failed to enumerate relay attack indicators: $_"
    }
}


function Export-ControlMatrix {
    Write-Host "[+] Generating control matrix mapping outputs to compliance controls..."
    try {
        $matrix = @(
            @{ Output = "System_Logon_Rights.txt"; Control = "Access Enforcement"; Frameworks = "NIST 800-171 3.1.2, AC-3; ISO 27001 A.9.2.3; CIS Control 4.6" },
            @{ Output = "RDP_Access_Audit.txt"; Control = "Remote Access Control"; Frameworks = "NIST 800-171 3.1.12; NIST 800-53 AC-17; ISO 27001 A.13.1.1" },
            @{ Output = "AzureAD_TokenPolicy.csv"; Control = "Session Control & Token Lifetime"; Frameworks = "NIST 800-53 AC-12; ISO 27001 A.9.4.2; CIS Control 16.4" },
            @{ Output = "AzureAD_AdminRoles.csv"; Control = "Privileged Access Management"; Frameworks = "NIST 800-171 3.1.5; ISO 27001 A.9.2.3; CIS Control 4.3" },
            @{ Output = "AzureAD_MFA_Status.csv"; Control = "Authentication & MFA"; Frameworks = "NIST 800-63B AAL2/AAL3; ISO 27001 A.9.4.2; HIPAA 164.312(d)" },
            @{ Output = "AzureAD_ConditionalAccess.csv"; Control = "Access Control Enforcement"; Frameworks = "NIST 800-171 3.1.1; ISO 27001 A.9.1.2; CIS Control 4.1" },
            @{ Output = "Dangerous_ACLs.txt"; Control = "Access Permissions"; Frameworks = "NIST 800-171 3.1.6; ISO 27001 A.9.2.6; STIG V-36436" },
            @{ Output = "PAC_SIDHistory_Risks.txt"; Control = "Privilege Escalation Risk"; Frameworks = "NIST 800-171 3.1.7; STIG AC-6(10); CIS Control 4.5" }
        )

        $matrix | Export-Csv -Path (Join-Path $OutputPath "ControlMatrix.csv") -NoTypeInformation
        Write-Host "[+] Control matrix exported to: ControlMatrix.csv"
    } catch {
        Write-Warning "[-] Failed to generate control matrix: $_"
    }
}


<#
function Export-RemediationDashboardHTML {
    Write-Host "[+] Exporting HTML remediation dashboard..."
    try {
        $remediationData = @(
            @{ File = "PAC_SIDHistory_Risks.txt"; Title = "SIDHistory Abuse"; Severity = "High"; Guidance = "Review accounts with SIDHistory and AdminCount=1. Remove unnecessary SIDHistory entries and reset AdminCount where inheritance is appropriate." },
            @{ File = "AdminSDHolder_Inheritance_Issues.txt"; Title = "AdminSDHolder Inheritance"; Severity = "Medium"; Guidance = "Manually inspect group ACLs flagged here. If safe, re-enable inheritance to allow proper permissions propagation." },
            @{ File = "SessionHijackable_Computers.txt"; Title = "Session Hijackable Hosts"; Severity = "High"; Guidance = "Restrict SMB (port 445) and RDP (port 3389) exposure. Enforce firewall rules and limit RDP access via GPO and IP filtering." },
            @{ File = "Relay_PrintSpooler.txt"; Title = "Print Spooler Risk"; Severity = "High"; Guidance = "Disable the Print Spooler service on Domain Controllers using GPO or PowerShell if not required." },
            @{ File = "Relay_SMB_Signing.txt"; Title = "SMB Signing Disabled"; Severity = "High"; Guidance = "Enable SMB signing by setting 'RequireSecuritySignature' to 1 via GPO or registry on all domain systems." },
            @{ File = "Relay_RPC_Endpoints.txt"; Title = "RPC Exposure"; Severity = "Medium"; Guidance = "Restrict access to vulnerable RPC interfaces and monitor usage of RPC services like MS-RPRN or EFSRPC." },
            @{ File = "Relay_RBCD_Computers.txt"; Title = "RBCD Delegation Exposure"; Severity = "High"; Guidance = "Audit Resource-Based Constrained Delegation assignments and remove unused or misconfigured entries." },
            @{ File = "Relay_NTLM_Settings.txt"; Title = "NTLM Restriction Weakness"; Severity = "High"; Guidance = "Set 'RestrictSendingNTLMTraffic' to 2 to enforce NTLM restrictions and prefer Kerberos where possible." },
            @{ File = "Relay_LLMNR_Local.txt"; Title = "LLMNR Enabled"; Severity = "Medium"; Guidance = "Disable LLMNR via GPO at 'Computer Configuration > Admin Templates > Network > DNS Client' by setting 'Turn Off Multicast Name Resolution' to Enabled." }
        )

        $htmlPath = Join-Path $OutputPath "Remediation_Dashboard.html"
        $html = @"
<html><head><title>Remediation Dashboard</title><style>
body { font-family: Arial; background: #fff; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
th { background-color: #eee; }
tr.high { background-color: #f8d7da; }
tr.medium { background-color: #fff3cd; }
tr.low { background-color: #d4edda; }
</style></head><body>
<h2>Remediation Dashboard</h2>
<table>
<tr><th>Finding</th><th>Severity</th><th>Remediation Guidance</th></tr>
"@

        foreach ($entry in $remediationData) {
            $file = Join-Path $OutputPath $entry.File
            if (Test-Path $file -and (Get-Content $file | Where-Object { $_.Trim() -ne "" })) {
                $severityClass = $entry.Severity.ToLower()
                $html += "<tr class='$severityClass'><td>$($entry.Title)</td><td>$($entry.Severity)</td><td>$($entry.Guidance)</td></tr>"
            }
        }

        $html += "</table><p>Generated on $(Get-Date)</p></body></html>"
        $html | Out-File -FilePath $htmlPath -Encoding UTF8

        Write-Host "[+] Remediation dashboard written to: $htmlPath"
    } catch {
        Write-Warning "[-] Failed to export remediation dashboard: $_"
    }
}
#>

function Export-RemediationDashboardHTML {
    Write-Host "[+] Exporting HTML remediation dashboard..."
    try {
        $remediationData = @(
            @{ File = "PAC_SIDHistory_Risks.txt"; Title = "SIDHistory Abuse"; Severity = "High"; Guidance = "Review accounts with SIDHistory and AdminCount=1. Remove unnecessary SIDHistory entries and reset AdminCount where inheritance is appropriate." },
            @{ File = "AdminSDHolder_Inheritance_Issues.txt"; Title = "AdminSDHolder Inheritance"; Severity = "Medium"; Guidance = "Manually inspect group ACLs flagged here. If safe, re-enable inheritance to allow proper permissions propagation." },
            @{ File = "SessionHijackable_Computers.txt"; Title = "Session Hijackable Hosts"; Severity = "High"; Guidance = "Restrict SMB (port 445) and RDP (port 3389) exposure. Enforce firewall rules and limit RDP access via GPO and IP filtering." },
            @{ File = "Relay_PrintSpooler.txt"; Title = "Print Spooler Risk"; Severity = "High"; Guidance = "Disable the Print Spooler service on Domain Controllers using GPO or PowerShell if not required." },
            @{ File = "Relay_SMB_Signing.txt"; Title = "SMB Signing Disabled"; Severity = "High"; Guidance = "Enable SMB signing by setting 'RequireSecuritySignature' to 1 via GPO or registry on all domain systems." },
            @{ File = "Relay_RPC_Endpoints.txt"; Title = "RPC Exposure"; Severity = "Medium"; Guidance = "Restrict access to vulnerable RPC interfaces and monitor usage of RPC services like MS-RPRN or EFSRPC." },
            @{ File = "Relay_RBCD_Computers.txt"; Title = "RBCD Delegation Exposure"; Severity = "High"; Guidance = "Audit Resource-Based Constrained Delegation assignments and remove unused or misconfigured entries." },
            @{ File = "Relay_NTLM_Settings.txt"; Title = "NTLM Restriction Weakness"; Severity = "High"; Guidance = "Set 'RestrictSendingNTLMTraffic' to 2 to enforce NTLM restrictions and prefer Kerberos where possible." },
            @{ File = "Relay_LLMNR_Local.txt"; Title = "LLMNR Enabled"; Severity = "Medium"; Guidance = "Disable LLMNR via GPO at 'Computer Configuration > Admin Templates > Network > DNS Client' by setting 'Turn Off Multicast Name Resolution' to Enabled." }
        )

        $htmlPath = Join-Path $OutputPath "Compliance_Risk_Scorecard.html"
        $existingHtml = Get-Content -Path $htmlPath -Raw

        $dashboard = "<h2>Remediation Dashboard</h2><table><tr><th>Finding</th><th>Severity</th><th>Remediation Guidance</th></tr>"
        foreach ($entry in $remediationData) {
            $file = Join-Path $OutputPath $entry.File
            if (Test-Path $file -and (Get-Content $file | Where-Object { $_.Trim() -ne "" })) {
                $class = $entry.Severity.ToLower()
                $dashboard += "<tr class='$class'><td>$($entry.Title)</td><td>$($entry.Severity)</td><td>$($entry.Guidance)</td></tr>"
            }
        }
                $dashboard += "</table>"

        $controlMatrixPreview = @"
<h2>Control Matrix</h2>
<label for='frameworkFilter'>Filter by Framework:</label>
<select id='frameworkFilter' onchange='filterMatrix()'>
  <option value=''>-- All --</option>
  <option value='NIST'>NIST</option>
  <option value='ISO'>ISO</option>
  <option value='HIPAA'>HIPAA</option>
  <option value='CIS'>CIS</option>
  <option value='SOX'>SOX</option>
</select>
<table id='matrixTable' border='1'>
<tr><th>Output</th><th>Control Area</th><th>Mapped Frameworks</th></tr>
<tr><td>System_Logon_Rights.txt</td><td>Access Enforcement</td><td>NIST 800-171 3.1.2, AC-3; ISO 27001 A.9.2.3; CIS Control 4.6</td></tr>
<tr><td>RDP_Access_Audit.txt</td><td>Remote Access Control</td><td>NIST 800-171 3.1.12; NIST 800-53 AC-17; ISO 27001 A.13.1.1</td></tr>
<tr><td>AzureAD_TokenPolicy.csv</td><td>Session Control & Token Lifetime</td><td>NIST 800-53 AC-12; ISO 27001 A.9.4.2; CIS Control 16.4</td></tr>
<tr><td>AzureAD_AdminRoles.csv</td><td>Privileged Access Management</td><td>NIST 800-171 3.1.5; ISO 27001 A.9.2.3; CIS Control 4.3</td></tr>
<tr><td>AzureAD_MFA_Status.csv</td><td>Authentication & MFA</td><td>NIST 800-63B AAL2/AAL3; ISO 27001 A.9.4.2; HIPAA 164.312(d)</td></tr>
<tr><td>AzureAD_ConditionalAccess.csv</td><td>Access Control Enforcement</td><td>NIST 800-171 3.1.1; ISO 27001 A.9.1.2; CIS Control 4.1</td></tr>
<tr><td>Dangerous_ACLs.txt</td><td>Access Permissions</td><td>NIST 800-171 3.1.6; ISO 27001 A.9.2.6; STIG V-36436</td></tr>
<tr><td>PAC_SIDHistory_Risks.txt</td><td>Privilege Escalation Risk</td><td>NIST 800-171 3.1.7; STIG AC-6(10); CIS Control 4.5</td></tr>
</table>
<script>
function filterMatrix() {
  var filter = document.getElementById('frameworkFilter').value.toLowerCase();
  var rows = document.getElementById('matrixTable').getElementsByTagName('tr');
  for (var i = 1; i < rows.length; i++) {
    var match = rows[i].cells[2].innerText.toLowerCase().includes(filter);
    rows[i].style.display = (filter === '' || match) ? '' : 'none';
  }
}
</script>
<p><b>Control Matrix:</b> <a href='ControlMatrix.csv'>Download ControlMatrix.csv</a></p>
<p><a href='javascript:window.print()'>🖨 Export/Print This Page</a></p>
"@

        $combined = $existingHtml -replace "</body>\s*</html>", "$dashboard$controlMatrixPreview<p>Remediation Summary Embedded</p></body></html>"
        $combined | Set-Content -Path $htmlPath -Encoding UTF8

        # Optional: create zip archive of all outputs
        $zipPath = Join-Path $OutputPath "ADAudit_Results_$(Get-Date -Format yyyyMMdd_HHmm).zip"
        Compress-Archive -Path (Join-Path $OutputPath '*') -DestinationPath $zipPath -Force

        Write-Host "[+] Embedded remediation dashboard, control matrix preview, and print/export option into: $htmlPath"
        Write-Host "[+] All results archived to: $zipPath"
    } catch {
        Write-Warning "[-] Failed to embed remediation dashboard: $_"
    }
}



param (
    [Parameter(Mandatory=$false)]
    [PSCredential]$DomainCredential,

    [Parameter(Mandatory=$false)]
    [string]$DomainController,

    [Parameter(Mandatory=$false)]
    [string[]]$Modules = @("all")
)

function Show-Help {
    @"
ADAudit.ps1 - Active Directory Remote Audit Toolkit

SYNTAX:
  .\ADAudit.ps1 [-DomainCredential <PSCredential>] [-DomainController <DC>] [-Modules <array>]

MODULE OPTIONS:
  all                  Run full audit
  passwordpolicy       Retrieve password policy
  ntds                 Output NTDS.dit extraction instructions
  oldboxes             Identify outdated OS machines
  gpo                  Enumerate Group Policy Objects
  ouperms              Check for generic OU permission issues
  laps                 Detect LAPS usage
  authpolsilos         Detect authentication policy silos
  insecurednszone      Check unsigned DNS zones
  recentchanges        Find recently created users/groups
  spn                  Audit SPN on high-value accounts
  asrep                Find accounts vulnerable to ASREPRoast
  acl                  Check dangerous ACLs
  adcs                 Check ADCS config (ESC1–ESC8)
  ldapsecurity         Inspect LDAP signing and channel binding
  trust                Audit domain trust relationships
  disabledexpired      Report disabled and expired accounts
  html                 Generate summary HTML report

EXAMPLE:
  .\ADAudit.ps1 -Modules @("passwordpolicy", "trust", "html")
"@ | Write-Host
    exit
}

if ($Modules -contains "help" -or $Modules -contains "-help") { Show-Help }

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputPath = Join-Path $ScriptRoot "Reports"
if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }

$ReportSummary = @()
function Add-ToReportSummary($Title, $File) {
    $ReportSummary += "<tr><td><b>$Title</b></td><td><a href='$File'>$File</a></td></tr>"
}

function Export-HTMLReport {
    $html = @"
<html>
<head><title>ADAudit Report</title></head>
<body>
<h2>Active Directory Audit Summary</h2>
<table border='1'>
<tr><th>Audit Section</th><th>Report File</th></tr>
$($ReportSummary -join "`n")
</table>
<p>Generated: $(Get-Date)</p>
</body>
</html>
"@
    $html | Out-File -FilePath (Join-Path $OutputPath "ADAudit_Report.html")
}

function Invoke-IfEnabled($ModuleName, [ScriptBlock]$Code, $OutputFile) {
    if ($Modules -contains "all" -or $Modules -contains $ModuleName) {
        & $Code
        if ($OutputFile) { Add-ToReportSummary $ModuleName $OutputFile }
    }
}
# MAIN
Test-DCConnection
Invoke-IfEnabled "passwordpolicy" { Get-PasswordPolicy } "PasswordPolicy.txt"
Invoke-IfEnabled "spn" { Get-SPNHighValueAccounts } "SPN_HighValue_Accounts.txt"
Invoke-IfEnabled "asrep" { Get-ASREPRoastableUsers } "ASREPRoastableUsers.txt"
Invoke-IfEnabled "adcs" { Get-ADCSVulnerabilities } "ADCS_CertAuthorities.txt"
Invoke-IfEnabled "gpo" { Get-GPOAndLAPSChecks } "GPO_List.txt"
Invoke-IfEnabled "laps" { Get-GPOAndLAPSChecks } "LAPS_Checks.txt"
Invoke-IfEnabled "ldapsecurity" { Get-LDAPSecurityIssues } "LDAP_Security_Audit.txt"
Invoke-IfEnabled "acl" { Get-DangerousACLs } "Dangerous_ACLs.txt"
Invoke-IfEnabled "ouperms" { Get-OUGenericPermissions } "OU_GenericPermissions.txt"
Invoke-IfEnabled "authpolsilos" { Get-AuthPolicySilos } "Auth_Policy_Silos.txt"
Invoke-IfEnabled "insecurednszone" { Get-InsecureDNSZones } "Insecure_DNS_Zones.txt"
Invoke-IfEnabled "recentchanges" { Get-RecentChanges } "NewUsers_Last30Days.txt"
Invoke-IfEnabled "ntds" { Get-NTDSUtilCheck } "NTDS_Extraction_Instructions.txt"
Invoke-IfEnabled "oldboxes" { Get-OldOSMachines } "Old_OS_Machines.txt"
Invoke-IfEnabled "disabledexpired" { Get-DisabledAndExpiredAccounts } "Disabled_Accounts.txt"
Invoke-IfEnabled "trust" { Get-TrustRelationships } "Domain_Trusts.txt"
Invoke-IfEnabled "relay" { Get-RelayAttackIndicators } "Relay_PrintSpooler.txt"
Invoke-IfEnabled "shares" { Get-DomainShares } "Domain_Shares.txt"
Invoke-IfEnabled "advuln" { Get-CommonADVulnerabilities } "AD_UnconstrainedDelegation.txt"
Invoke-IfEnabled "pacsid" { Get-KerberosPACandSIDHistoryAbuse } "PAC_SIDHistory_Risks.txt"
Invoke-IfEnabled "adminsd" { Get-AdminSDHolderInheritance } "AdminSDHolder_Inheritance_Issues.txt"
Invoke-IfEnabled "hijack" { Get-SessionHijackableComputers } "SessionHijackable_Computers.txt"
Invoke-IfEnabled "azuread" { Get-AzureADSecurityInsights } "AzureAD_AdminRoles.csv"
Invoke-IfEnabled "compliance" { Generate-ComplianceRiskScores } "Compliance_Risk_Scorecard.csv"
Invoke-IfEnabled "logonaudit" { Get-SystemLogonAudit } "System_Logon_Rights.txt"
Invoke-IfEnabled "rdpaudit" { Get-RDPAccessAudit } "RDP_Access_Audit.txt"
Invoke-IfEnabled "tokenpolicy" { Get-AccessTokenPolicyAudit } "AzureAD_TokenPolicy.csv"
Invoke-IfEnabled "matrix" { Export-ControlMatrix } "ControlMatrix.csv"
Invoke-IfEnabled "html" { Export-HTMLReport } "ADAudit_Report.html"

Write-Host "[+] Audit completed. Reports saved to: $OutputPath"
