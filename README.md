# 🔍 Unified Active Directory Security Audit Tool

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell) [![License](https://img.shields.io/badge/License-MIT-green.svg)](https://claude.ai/chat/LICENSE) [![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows) [![AD](https://img.shields.io/badge/Active%20Directory-2008%2B-orange.svg)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)

A comprehensive PowerShell-based Active Directory security assessment platform that combines multiple audit modules into a single, powerful tool for security professionals, system administrators, and penetration testers.

## 🌟 **Key Features**

### 🔧 **Comprehensive Assessment Modules**
# 🔍 Unified Active Directory Security Audit Tool

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell) [![License](https://img.shields.io/badge/License-MIT-green.svg)](https://claude.ai/chat/LICENSE) [![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows) [![AD](https://img.shields.io/badge/Active%20Directory-2008%2B-orange.svg)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)

A comprehensive PowerShell-based Active Directory security assessment platform that combines multiple audit modules into a single, powerful tool for security professionals, system administrators, and penetration testers.

## 🌟 **Key Features**

### 🔧 **Comprehensive Assessment Modules**

- **Core AD Enumeration**: Users, groups, computers, organizational units
- **LDAP Domain Intelligence**: Complete directory dump with JSON/HTML output
- **Security Analysis**: Kerberoasting, ASREPRoast, delegation vulnerabilities
- **Kerberos Assessment**: Ticket policies, encryption weaknesses
- **Certificate Services Audit**: PKI vulnerabilities, ESC attack vectors
- **Trust Relationship Analysis**: Domain/forest trusts, SID history abuse
- **Delegation Security Review**: Unconstrained, constrained, and resource-based delegation
- **Compliance Reporting**: Security baseline assessment and scoring

### 📊 **Professional Reporting**

- **Interactive HTML Dashboards**: Executive and technical views
- **JSON Export**: Machine-readable data (ldapdomaindump-style)
- **CSV Reports**: Spreadsheet-compatible data exports
- **XML Reports**: Structured technical documentation
- **Executive Summaries**: Business-focused findings and recommendations

### 🛠️ **Advanced Capabilities**

- **Multi-threaded execution** for improved performance
- **Automated remediation guides** with PowerShell scripts
- **Risk scoring and prioritization** framework
- **Interactive and non-interactive modes**
- **Comprehensive logging and error handling**
- **Evidence collection** and documentation

## 📋 **Table of Contents**

- [Installation](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-installation)
- [Quick Start](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-quick-start)
- [Usage Examples](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-usage-examples)
- [Detailed Walkthroughs](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-detailed-walkthroughs)
- [Module Documentation](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-module-documentation)
- [Output Structure](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-output-structure)
- [Prerequisites](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-prerequisites)
- [Security Considerations](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-security-considerations)
- [Contributing](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-contributing)
- [License](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-license)

## 🚀 **Installation**

### **Option 1: Direct Download**

```powershell
# Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/javalogicuser/remy-AD/refs/heads/main/remy-ad-audit.ps1" -OutFile "remy-ad-audit.ps1"

# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### **Option 2: Git Clone**

```bash
git clone https://github.com/javalogicuser/remy-AD.git
cd remy-AD
```

### **Option 3: PowerShell Gallery** _(Coming Soon)_

```powershell
Install-Module -Name RemyADAudit
```

## ⚡ **Quick Start**

### **1. Basic Interactive Assessment**

```powershell
# Navigate to script directory
cd C:\path\to\remy-ad-audit

# Run with interactive prompts
.\remy-ad-audit.ps1
```

### **2. Quick Automated Assessment**

```powershell
# Run with minimal parameters
.\remy-ad-audit.ps1 -DomainController "dc01.corp.local" -DomainName "corp.local" -SkipPrompts
```

### **3. Security-Focused Assessment**

```powershell
# Focus on security vulnerabilities
.\remy-ad-audit.ps1 -DomainController "192.168.1.10" -DomainName "corp.local" -Modules @('security','kerberos','certificates') -SkipPrompts
```

## 📚 **Usage Examples**

### **Example 1: Complete Domain Assessment**

```powershell
.\remy-ad-audit.ps1 `
    -DomainController "dc01.corp.local" `
    -DomainName "corp.local" `
    -Modules @('all') `
    -Format "All" `
    -IncludeRemediation `
    -SkipPrompts
```

**Output**: Complete security assessment with all modules, full reporting suite, and remediation guides.

### **Example 2: Kerberos Security Focus**

```powershell
.\remy-ad-audit.ps1 `
    -DomainController "10.0.0.100" `
    -DomainName "internal.company.com" `
    -Modules @('kerberos','security') `
    -Format "HTML" `
    -Threads 20 `
    -SkipPrompts
```

**Output**: Focused analysis on Kerberos vulnerabilities with HTML dashboard.

### **Example 3: Compliance Assessment**

```powershell
$creds = Get-Credential
.\remy-ad-audit.ps1 `
    -DomainController "dc.enterprise.local" `
    -DomainName "enterprise.local" `
    -Credential $creds `
    -Modules @('compliance','core') `
    -ComplianceReport `
    -OutputPath "C:\Audit_Reports" `
    -SkipPrompts
```

**Output**: Compliance-focused assessment with custom credentials and specified output location.

### **Example 4: Certificate Services Audit**

```powershell
.\remy-ad-audit.ps1 `
    -DomainController "pki-dc.corp.local" `
    -DomainName "corp.local" `
    -Modules @('certificates','security') `
    -Format "JSON" `
    -Verbose `
    -SkipPrompts
```

**Output**: PKI security assessment with detailed JSON output and verbose logging.

## 🎯 **Detailed Walkthroughs**

### **Walkthrough 1: First-Time Security Assessment**

#### **Step 1: Preparation**

```powershell
# Ensure you have appropriate permissions
whoami /groups | findstr "Domain Admins\|Enterprise Admins"

# Check PowerShell version
$PSVersionTable.PSVersion
```

#### **Step 2: Basic Assessment**

```powershell
# Start with interactive mode for first run
.\remy-ad-audit.ps1

# Follow prompts:
# 🌐 Enter Domain Controller: dc01.corp.local
# 🏢 Enter Domain Name: corp.local
# 🔐 Use alternate credentials? N
# 🧩 Enter modules: all
# 📁 Output Directory: [Enter for default]
```

#### **Step 3: Review Results**

```powershell
# HTML dashboard opens automatically
# Navigate to: $env:TEMP\AD_Audit_Reports_[timestamp]\Reports\HTML\AD_Audit_Dashboard.html

# Review executive summary
Get-Content "$env:TEMP\AD_Audit_Reports_*\Executive_Summary.txt"
```

### **Walkthrough 2: Advanced Security Assessment**

#### **Step 1: Environment Setup**

```powershell
# Create dedicated audit user (recommended)
New-ADUser -Name "AuditUser" -SamAccountName "audituser" -UserPrincipalName "audituser@corp.local"
Add-ADGroupMember -Identity "Domain Admins" -Members "audituser"

# Store credentials securely
$securePassword = Read-Host "Enter audit user password" -AsSecureString
$auditCreds = New-Object System.Management.Automation.PSCredential("corp\audituser", $securePassword)
```

#### **Step 2: Comprehensive Audit**

```powershell
.\remy-ad-audit.ps1 `
    -DomainController "dc01.corp.local" `
    -DomainName "corp.local" `
    -Credential $auditCreds `
    -Modules @('core','security','kerberos','certificates','trusts','delegation','compliance') `
    -Format "All" `
    -OutputPath "C:\SecurityAudits\$(Get-Date -Format 'yyyyMMdd')" `
    -IncludeRemediation `
    -ComplianceReport `
    -Threads 15 `
    -Verbose `
    -SkipPrompts
```

#### **Step 3: Analysis and Reporting**

```powershell
# Review high-risk findings
$jsonReport = Get-Content "C:\SecurityAudits\*\Reports\JSON\AD_Audit_Complete.json" | ConvertFrom-Json
$jsonReport.Statistics

# Generate custom report
$highRiskFindings = $jsonReport.Findings | Where-Object {$_.Risk -eq "High"}
$highRiskFindings | Export-Csv "C:\SecurityAudits\HighRisk_Summary.csv" -NoTypeInformation
```

### **Walkthrough 3: Penetration Testing Integration**

#### **Step 1: Reconnaissance Phase**

```powershell
# Start with LDAP domain dump
.\remy-ad-audit.ps1 `
    -DomainController "192.168.1.10" `
    -DomainName "target.local" `
    -Modules @('ldap','core') `
    -Format "JSON" `
    -OutputPath "C:\PenTest\Recon" `
    -SkipPrompts
```

#### **Step 2: Vulnerability Analysis**

```powershell
# Focus on attack vectors
.\remy-ad-audit.ps1 `
    -DomainController "192.168.1.10" `
    -DomainName "target.local" `
    -Modules @('security','kerberos','delegation') `
    -Format "JSON" `
    -OutputPath "C:\PenTest\Vulns" `
    -SkipPrompts
```

#### **Step 3: Evidence Collection**

```powershell
# Combine results for reporting
$reconData = Get-Content "C:\PenTest\Recon\Reports\JSON\*.json" | ConvertFrom-Json
$vulnData = Get-Content "C:\PenTest\Vulns\Reports\JSON\*.json" | ConvertFrom-Json

# Create evidence package
Compress-Archive -Path "C:\PenTest\*" -DestinationPath "C:\Evidence\AD_Assessment_$(Get-Date -Format 'yyyyMMdd').zip"
```

## 📖 **Module Documentation**

### **Core Module (`-Modules core`)**

**Purpose**: Fundamental AD enumeration and baseline data collection

**Capabilities**:

- Domain information gathering
- User account enumeration
- Computer account discovery
- Group membership analysis
- Organizational unit structure
- Domain controller identification

**Output**: User lists, computer inventories, group hierarchies

### **LDAP Module (`-Modules ldap`)**

**Purpose**: Comprehensive directory intelligence gathering

**Capabilities**:

- Complete LDAP tree enumeration
- Schema analysis
- Attribute extraction
- Permission mapping
- ldapdomaindump-style output

**Output**: JSON domain dump, LDAP tree structure, schema documentation

### **Security Module (`-Modules security`)**

**Purpose**: Core security vulnerability identification

**Capabilities**:

- Privileged account analysis
- Password policy assessment
- Account lockout configuration
- Stale account identification
- Permission auditing
- Security group analysis

**Output**: Security findings, privileged user lists, policy compliance reports

### **Kerberos Module (`-Modules kerberos`)**

**Purpose**: Kerberos protocol security assessment

**Capabilities**:

- Kerberoastable account identification
- ASREPRoast vulnerability detection
- Encryption algorithm analysis
- Ticket lifetime evaluation
- SPN enumeration

**Output**: Kerberoastable users, weak encryption findings, ticket policy analysis

### **Certificates Module (`-Modules certificates`)**

**Purpose**: PKI infrastructure security review

**Capabilities**:

- Certificate Authority enumeration
- Certificate template analysis
- ESC vulnerability detection (ESC1-ESC8)
- Certificate permission auditing
- Expired certificate identification

**Output**: PKI security findings, vulnerable templates, certificate inventories

### **Trusts Module (`-Modules trusts`)**

**Purpose**: Trust relationship security analysis

**Capabilities**:

- Domain trust enumeration
- Forest trust analysis
- External trust review
- SID history detection
- Trust security assessment

**Output**: Trust relationship maps, SID history findings, trust security recommendations

### **Delegation Module (`-Modules delegation`)**

**Purpose**: Delegation configuration security review

**Capabilities**:

- Unconstrained delegation detection
- Constrained delegation analysis
- Resource-based constrained delegation review
- Delegation vulnerability assessment

**Output**: Delegation findings, security recommendations, configuration analysis

### **Compliance Module (`-Modules compliance`)**

**Purpose**: Security baseline and compliance assessment

**Capabilities**:

- Password policy compliance
- Account lockout policy review
- Audit policy assessment
- Security setting evaluation
- Compliance scoring

**Output**: Compliance scorecards, policy gap analysis, remediation recommendations

## 📁 **Output Structure**

```
AD_Audit_Reports_YYYYMMDD_HHMMSS/
├── 📊 Reports/
│   ├── 🌐 HTML/
│   │   ├── AD_Audit_Dashboard.html          # Interactive security dashboard
│   │   ├── Executive_Summary.html           # High-level findings
│   │   ├── Technical_Details.html           # Detailed technical analysis
│   │   └── Compliance_Report.html           # Compliance assessment
│   ├── 📄 JSON/
│   │   ├── AD_Audit_Complete.json           # Complete audit data
│   │   ├── ldapdomaindump_style.json        # LDAP domain dump
│   │   ├── Security_Findings.json           # Security vulnerabilities
│   │   └── Compliance_Results.json          # Compliance assessment
│   ├── 📈 CSV/
│   │   ├── Users.csv                        # User account data
│   │   ├── Computers.csv                    # Computer account data
│   │   ├── Groups.csv                       # Group information
│   │   ├── Security_Issues.csv              # Security findings
│   │   └── Kerberoastable_Users.csv         # Kerberoastable accounts
│   └── 📋 XML/
│       └── AD_Audit_Report.xml              # Structured XML report
├── 💾 Data/
│   ├── 🔧 Core/
│   │   ├── domain_info.json                 # Domain metadata
│   │   ├── users_raw.json                   # Raw user data
│   │   └── computers_raw.json               # Raw computer data
│   ├── 🛡️ Security/
│   │   ├── vulnerabilities.json             # Security vulnerabilities
│   │   ├── privileged_users.json            # Privileged accounts
│   │   └── security_policies.json           # Security configuration
│   ├── 🎫 Kerberos/
│   │   ├── kerberoastable.json              # Kerberoastable accounts
│   │   ├── asreproastable.json              # ASREPRoastable accounts
│   │   └── kerberos_policy.json             # Kerberos settings
│   ├── 📜 Certificates/
│   │   ├── certificate_authorities.json     # CA information
│   │   ├── certificate_templates.json       # Template analysis
│   │   └── esc_vulnerabilities.json         # ESC findings
│   └── 🤝 Trusts/
│       ├── domain_trusts.json               # Trust relationships
│       └── sid_history.json                 # SID history findings
├── 🛠️ Remediation/
│   ├── 📜 Scripts/
│   │   ├── AD_Security_Remediation.ps1      # Automated fixes
│   │   ├── Disable_Inactive_Users.ps1       # User cleanup
│   │   ├── Fix_Kerberos_Issues.ps1          # Kerberos hardening
│   │   └── Certificate_Cleanup.ps1          # PKI security fixes
│   └── 📖 Guides/
│       ├── Security_Remediation_Guide.md    # Step-by-step fixes
│       ├── Kerberos_Hardening_Guide.md      # Kerberos security
│       ├── PKI_Security_Guide.md            # Certificate services
│       └── Compliance_Implementation.md     # Compliance guidance
├── 🔍 Evidence/
│   ├── 📸 Screenshots/                      # Visual evidence
│   ├── 📝 Logs/
│   │   ├── audit.log                        # Detailed audit log
│   │   ├── errors.log                       # Error tracking
│   │   └── performance.log                  # Performance metrics
│   └── 🗂️ Archives/
│       └── raw_data_backup.zip              # Complete data backup
├── 📋 Executive_Summary.txt                 # Business summary
├── 🔧 Configuration.json                    # Audit configuration
└── 📊 Statistics.json                       # Audit statistics
```

## ⚙️ **Prerequisites**

### **System Requirements**

- **Operating System**: Windows 10/11, Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **Memory**: Minimum 4GB RAM (8GB+ recommended for large environments)
- **Disk Space**: 1GB+ free space for reports and logs
- **Network**: Access to domain controllers on ports 389 (LDAP) and 636 (LDAPS)

### **Permissions Required**

- **Domain User**: Minimum for basic enumeration
- **Domain Admin**: Recommended for comprehensive assessment
- **Enterprise Admin**: Required for forest-level analysis
- **Local Admin**: For advanced certificate and delegation analysis

### **Optional Components**

- **Active Directory PowerShell Module**: Enhanced functionality
- **RSAT Tools**: Additional administrative capabilities
- **Certificate Services Tools**: PKI analysis features

### **PowerShell Modules** _(Auto-detected)_

```powershell
# Check for required modules
Get-Module -ListAvailable ActiveDirectory
Get-WindowsFeature -Name RSAT-AD-PowerShell
```

## 🔒 **Security Considerations**

### **Authentication Security**

- **Use dedicated audit accounts** with minimal required privileges
- **Implement service accounts** for automated assessments
- **Rotate credentials regularly** after assessments
- **Log all audit activities** for compliance tracking

### **Data Protection**

- **Encrypt output files** containing sensitive information
- **Secure transfer methods** for audit reports
- **Implement data retention policies** for audit artifacts
- **Access controls** on audit results and logs

### **Network Security**

- **Use encrypted connections** (LDAPS) when available
- **Monitor network traffic** during assessments
- **Implement network segmentation** for audit activities
- **Rate limiting** to avoid overwhelming domain controllers

### **Operational Security**

```powershell
# Example: Secure credential handling
$securePassword = Read-Host "Enter password" -AsSecureString
$credential = New-Object System.Management.Automation.PSCredential("domain\user", $securePassword)

# Example: Encrypted output
$auditData | ConvertTo-Json | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Set-Content "encrypted_audit.txt"
```

### **Compliance Requirements**

- **Document authorization** before conducting assessments
- **Maintain audit trails** of all activities
- **Follow data handling procedures** per organizational policies
- **Report findings** through established security channels

## 🎛️ **Advanced Configuration**

### **Custom Module Development**

```powershell
# Example: Custom security check module
function Invoke-CustomSecurityCheck {
    Write-Log "🔍 Running custom security checks..." -Level Info
    
    $customResults = @{
        CustomFindings = @()
        RiskScore = 0
    }
    
    # Your custom logic here
    
    $Global:Config.Results.Custom = $customResults
    Write-Log "✅ Custom security check completed" -Level Success
}

# Add to main execution flow
$Global:Config.Modules += 'custom'
```

### **Integration with SIEM/SOAR**

```powershell
# Example: Send results to SIEM
$auditResults = Get-Content "Reports\JSON\AD_Audit_Complete.json" | ConvertFrom-Json

# Send to Splunk
$splunkUri = "https://splunk.company.com:8088/services/collector"
$headers = @{"Authorization" = "Splunk $splunkToken"}
Invoke-RestMethod -Uri $splunkUri -Method Post -Headers $headers -Body ($auditResults | ConvertTo-Json)

# Send to Microsoft Sentinel
$workspaceId = "your-workspace-id"
$sharedKey = "your-shared-key"
Send-LogAnalyticsData -WorkspaceId $workspaceId -SharedKey $sharedKey -Body ($auditResults | ConvertTo-Json) -LogType "ADSecurityAudit"
```

### **Automated Scheduling**

```powershell
# Example: Scheduled task for weekly audits
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\remy-ad-audit.ps1 -SkipPrompts"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2AM
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "Weekly AD Security Audit" -Action $action -Trigger $trigger -Settings $settings
```

## 🚨 **Troubleshooting**

### **Common Issues and Solutions**

#### **Issue**: "Access Denied" errors during enumeration

```powershell
# Solution: Check permissions and use appropriate credentials
$testAccess = Test-ADAuthentication -Credential $credential
if (-not $testAccess) {
    Write-Warning "Insufficient permissions. Ensure audit account has required privileges."
}
```

#### **Issue**: Script execution policy errors

```powershell
# Solution: Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or bypass for single execution
PowerShell.exe -ExecutionPolicy Bypass -File .\remy-ad-audit.ps1
```

#### **Issue**: Module import failures

```powershell
# Solution: Install required modules
Install-WindowsFeature -Name RSAT-AD-PowerShell
Import-Module ActiveDirectory -Force
```

#### **Issue**: Network connectivity problems

```powershell
# Solution: Test connectivity and firewall rules
Test-NetConnection -ComputerName "dc01.corp.local" -Port 389
Test-NetConnection -ComputerName "dc01.corp.local" -Port 636
```

### **Debug Mode**

```powershell
# Enable verbose logging and debug output
.\remy-ad-audit.ps1 -Verbose -Debug -DomainController "dc01.corp.local" -DomainName "corp.local"

# Check log files for detailed error information
Get-Content "$env:TEMP\AD_Audit_Reports_*\audit.log" | Select-String "ERROR"
```

### **Performance Optimization**

```powershell
# Optimize for large environments
.\remy-ad-audit.ps1 `
    -DomainController "dc01.corp.local" `
    -DomainName "corp.local" `
    -Threads 25 `                     # Increase thread count
    -Modules @('core','security') `   # Run fewer modules
    -Format "JSON" `                  # Use faster output format
    -SkipPrompts
```

## 🤝 **Contributing**

We welcome contributions from the security community! Here's how you can help:

### **Ways to Contribute**

- 🐛 **Bug Reports**: Report issues and provide reproduction steps
- 💡 **Feature Requests**: Suggest new modules or capabilities
- 🔧 **Code Contributions**: Submit pull requests with improvements
- 📖 **Documentation**: Improve guides and examples
- 🧪 **Testing**: Test in different environments and provide feedback

### **Development Setup**

```bash
# Fork the repository
git clone https://github.com/yourusername/remy-ad-audit.git
cd remy-ad-audit

# Create feature branch
git checkout -b feature/new-security-module

# Make changes and test
.\remy-ad-audit.ps1 -DomainController "testdc.lab.local" -DomainName "lab.local" -SkipPrompts

# Commit and push
git add .
git commit -m "Add new security module for XYZ analysis"
git push origin feature/new-security-module

# Create pull request
```

### **Code Standards**

- Follow PowerShell best practices and style guidelines
- Include comprehensive error handling
- Add detailed comments and documentation
- Include parameter validation and help text
- Test thoroughly in lab environments

### **Security Disclosure**

For security vulnerabilities in the tool itself:

- Email: ethicalsoup@gmail.com
- Include detailed reproduction steps
- Allow 90 days for responsible disclosure

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](https://claude.ai/chat/LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Unified AD Audit Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 🙏 **Acknowledgments**

- **Microsoft Active Directory Team** - For comprehensive AD documentation
- **PowerShell Community** - For excellent modules and best practices
- **Security Research Community** - For attack techniques and defense strategies
- **Open Source Contributors** - For inspiration and code examples

## 📞 **Support and Contact**

### **Community Support**

- **GitHub Issues**: [Report bugs and request features](https://github.com/yourusername/remy-ad-audit/issues)
- **Discussions**: [Community Q&A and tips](https://github.com/yourusername/remy-ad-audit/discussions)
- **Wiki**: [Additional documentation and guides](https://github.com/yourusername/remy-ad-audit/wiki)

### **Professional Support**

- **Email**: ethicalsoup@gmail.com
- **Documentation**: [Comprehensive guides and API reference](https://docs.yourorganization.com/remy-ad-audit)
- **Training**: Custom training sessions available for enterprise customers

### **Stay Updated**

- ⭐ **Star this repository** to stay notified of updates
- 👀 **Watch releases** for new versions and security updates
- 📢 **Follow on Twitter**: [@ethicalsoup](https://twitter.com/ethicalsoup)

---

## 🔗 **Quick Links**

|Resource|Description|Link|
|---|---|---|
|🚀 **Quick Start Guide**|Get up and running in 5 minutes|[Quick Start](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-quick-start)|
|📖 **Module Documentation**|Detailed module capabilities|[Modules](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-module-documentation)|
|🎯 **Walkthroughs**|Step-by-step usage examples|[Walkthroughs](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-detailed-walkthroughs)|
|🔧 **Troubleshooting**|Common issues and solutions|[Troubleshooting](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-troubleshooting)|
|🤝 **Contributing**|Help improve the project|[Contributing](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-contributing)|
|📄 **License**|Usage terms and conditions|[License](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-license)|

---

**⚠️ Important**: This tool is for authorized security assessments only. Ensure you have proper authorization before running against any Active Directory environment. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

**📊 Project Statistics**: ![GitHub stars](https://img.shields.io/github/stars/yourusername/remy-ad-audit) ![GitHub forks](https://img.shields.io/github/forks/yourusername/remy-ad-audit) ![GitHub issues](https://img.shields.io/github/issues/yourusername/remy-ad-audit) ![GitHub last commit](https://github.com/javalogicuser/remy-AD)
- **Core AD Enumeration**: Users, groups, computers, organizational units
- **LDAP Domain Intelligence**: Complete directory dump with JSON/HTML output
- **Security Analysis**: Kerberoasting, ASREPRoast, delegation vulnerabilities
- **Kerberos Assessment**: Ticket policies, encryption weaknesses
- **Certificate Services Audit**: PKI vulnerabilities, ESC attack vectors
- **Trust Relationship Analysis**: Domain/forest trusts, SID history abuse
- **Delegation Security Review**: Unconstrained, constrained, and resource-based delegation
- **Compliance Reporting**: Security baseline assessment and scoring

### 📊 **Professional Reporting**

- **Interactive HTML Dashboards**: Executive and technical views
- **JSON Export**: Machine-readable data (ldapdomaindump-style)
- **CSV Reports**: Spreadsheet-compatible data exports
- **XML Reports**: Structured technical documentation
- **Executive Summaries**: Business-focused findings and recommendations

### 🛠️ **Advanced Capabilities**

- **Multi-threaded execution** for improved performance
- **Automated remediation guides** with PowerShell scripts
- **Risk scoring and prioritization** framework
- **Interactive and non-interactive modes**
- **Comprehensive logging and error handling**
- **Evidence collection** and documentation

## 📋 **Table of Contents**

- [Installation](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-installation)
- [Quick Start](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-quick-start)
- [Usage Examples](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-usage-examples)
- [Detailed Walkthroughs](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-detailed-walkthroughs)
- [Module Documentation](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-module-documentation)
- [Output Structure](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-output-structure)
- [Prerequisites](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-prerequisites)
- [Security Considerations](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-security-considerations)
- [Contributing](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-contributing)
- [License](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-license)

## 🚀 **Installation**

### **Option 1: Direct Download**

```powershell
# Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yourusername/unified-ad-audit/main/unified-ad-audit.ps1" -OutFile "unified-ad-audit.ps1"

# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### **Option 2: Git Clone**

```bash
git clone https://github.com/yourusername/unified-ad-audit.git
cd unified-ad-audit
```

### **Option 3: PowerShell Gallery** _(Coming Soon)_

```powershell
Install-Module -Name UnifiedADAudit
```

## ⚡ **Quick Start**

### **1. Basic Interactive Assessment**

```powershell
# Navigate to script directory
cd C:\path\to\unified-ad-audit

# Run with interactive prompts
.\unified-ad-audit.ps1
```

### **2. Quick Automated Assessment**

```powershell
# Run with minimal parameters
.\unified-ad-audit.ps1 -DomainController "dc01.corp.local" -DomainName "corp.local" -SkipPrompts
```

### **3. Security-Focused Assessment**

```powershell
# Focus on security vulnerabilities
.\unified-ad-audit.ps1 -DomainController "192.168.1.10" -DomainName "corp.local" -Modules @('security','kerberos','certificates') -SkipPrompts
```

## 📚 **Usage Examples**

### **Example 1: Complete Domain Assessment**

```powershell
.\unified-ad-audit.ps1 `
    -DomainController "dc01.corp.local" `
    -DomainName "corp.local" `
    -Modules @('all') `
    -Format "All" `
    -IncludeRemediation `
    -SkipPrompts
```

**Output**: Complete security assessment with all modules, full reporting suite, and remediation guides.

### **Example 2: Kerberos Security Focus**

```powershell
.\unified-ad-audit.ps1 `
    -DomainController "10.0.0.100" `
    -DomainName "internal.company.com" `
    -Modules @('kerberos','security') `
    -Format "HTML" `
    -Threads 20 `
    -SkipPrompts
```

**Output**: Focused analysis on Kerberos vulnerabilities with HTML dashboard.

### **Example 3: Compliance Assessment**

```powershell
$creds = Get-Credential
.\unified-ad-audit.ps1 `
    -DomainController "dc.enterprise.local" `
    -DomainName "enterprise.local" `
    -Credential $creds `
    -Modules @('compliance','core') `
    -ComplianceReport `
    -OutputPath "C:\Audit_Reports" `
    -SkipPrompts
```

**Output**: Compliance-focused assessment with custom credentials and specified output location.

### **Example 4: Certificate Services Audit**

```powershell
.\unified-ad-audit.ps1 `
    -DomainController "pki-dc.corp.local" `
    -DomainName "corp.local" `
    -Modules @('certificates','security') `
    -Format "JSON" `
    -Verbose `
    -SkipPrompts
```

**Output**: PKI security assessment with detailed JSON output and verbose logging.

## 🎯 **Detailed Walkthroughs**

### **Walkthrough 1: First-Time Security Assessment**

#### **Step 1: Preparation**

```powershell
# Ensure you have appropriate permissions
whoami /groups | findstr "Domain Admins\|Enterprise Admins"

# Check PowerShell version
$PSVersionTable.PSVersion
```

#### **Step 2: Basic Assessment**

```powershell
# Start with interactive mode for first run
.\unified-ad-audit.ps1

# Follow prompts:
# 🌐 Enter Domain Controller: dc01.corp.local
# 🏢 Enter Domain Name: corp.local
# 🔐 Use alternate credentials? N
# 🧩 Enter modules: all
# 📁 Output Directory: [Enter for default]
```

#### **Step 3: Review Results**

```powershell
# HTML dashboard opens automatically
# Navigate to: $env:TEMP\AD_Audit_Reports_[timestamp]\Reports\HTML\AD_Audit_Dashboard.html

# Review executive summary
Get-Content "$env:TEMP\AD_Audit_Reports_*\Executive_Summary.txt"
```

### **Walkthrough 2: Advanced Security Assessment**

#### **Step 1: Environment Setup**

```powershell
# Create dedicated audit user (recommended)
New-ADUser -Name "AuditUser" -SamAccountName "audituser" -UserPrincipalName "audituser@corp.local"
Add-ADGroupMember -Identity "Domain Admins" -Members "audituser"

# Store credentials securely
$securePassword = Read-Host "Enter audit user password" -AsSecureString
$auditCreds = New-Object System.Management.Automation.PSCredential("corp\audituser", $securePassword)
```

#### **Step 2: Comprehensive Audit**

```powershell
.\unified-ad-audit.ps1 `
    -DomainController "dc01.corp.local" `
    -DomainName "corp.local" `
    -Credential $auditCreds `
    -Modules @('core','security','kerberos','certificates','trusts','delegation','compliance') `
    -Format "All" `
    -OutputPath "C:\SecurityAudits\$(Get-Date -Format 'yyyyMMdd')" `
    -IncludeRemediation `
    -ComplianceReport `
    -Threads 15 `
    -Verbose `
    -SkipPrompts
```

#### **Step 3: Analysis and Reporting**

```powershell
# Review high-risk findings
$jsonReport = Get-Content "C:\SecurityAudits\*\Reports\JSON\AD_Audit_Complete.json" | ConvertFrom-Json
$jsonReport.Statistics

# Generate custom report
$highRiskFindings = $jsonReport.Findings | Where-Object {$_.Risk -eq "High"}
$highRiskFindings | Export-Csv "C:\SecurityAudits\HighRisk_Summary.csv" -NoTypeInformation
```

### **Walkthrough 3: Penetration Testing Integration**

#### **Step 1: Reconnaissance Phase**

```powershell
# Start with LDAP domain dump
.\unified-ad-audit.ps1 `
    -DomainController "192.168.1.10" `
    -DomainName "target.local" `
    -Modules @('ldap','core') `
    -Format "JSON" `
    -OutputPath "C:\PenTest\Recon" `
    -SkipPrompts
```

#### **Step 2: Vulnerability Analysis**

```powershell
# Focus on attack vectors
.\unified-ad-audit.ps1 `
    -DomainController "192.168.1.10" `
    -DomainName "target.local" `
    -Modules @('security','kerberos','delegation') `
    -Format "JSON" `
    -OutputPath "C:\PenTest\Vulns" `
    -SkipPrompts
```

#### **Step 3: Evidence Collection**

```powershell
# Combine results for reporting
$reconData = Get-Content "C:\PenTest\Recon\Reports\JSON\*.json" | ConvertFrom-Json
$vulnData = Get-Content "C:\PenTest\Vulns\Reports\JSON\*.json" | ConvertFrom-Json

# Create evidence package
Compress-Archive -Path "C:\PenTest\*" -DestinationPath "C:\Evidence\AD_Assessment_$(Get-Date -Format 'yyyyMMdd').zip"
```

## 📖 **Module Documentation**

### **Core Module (`-Modules core`)**

**Purpose**: Fundamental AD enumeration and baseline data collection

**Capabilities**:

- Domain information gathering
- User account enumeration
- Computer account discovery
- Group membership analysis
- Organizational unit structure
- Domain controller identification

**Output**: User lists, computer inventories, group hierarchies

### **LDAP Module (`-Modules ldap`)**

**Purpose**: Comprehensive directory intelligence gathering

**Capabilities**:

- Complete LDAP tree enumeration
- Schema analysis
- Attribute extraction
- Permission mapping
- ldapdomaindump-style output

**Output**: JSON domain dump, LDAP tree structure, schema documentation

### **Security Module (`-Modules security`)**

**Purpose**: Core security vulnerability identification

**Capabilities**:

- Privileged account analysis
- Password policy assessment
- Account lockout configuration
- Stale account identification
- Permission auditing
- Security group analysis

**Output**: Security findings, privileged user lists, policy compliance reports

### **Kerberos Module (`-Modules kerberos`)**

**Purpose**: Kerberos protocol security assessment

**Capabilities**:

- Kerberoastable account identification
- ASREPRoast vulnerability detection
- Encryption algorithm analysis
- Ticket lifetime evaluation
- SPN enumeration

**Output**: Kerberoastable users, weak encryption findings, ticket policy analysis

### **Certificates Module (`-Modules certificates`)**

**Purpose**: PKI infrastructure security review

**Capabilities**:

- Certificate Authority enumeration
- Certificate template analysis
- ESC vulnerability detection (ESC1-ESC8)
- Certificate permission auditing
- Expired certificate identification

**Output**: PKI security findings, vulnerable templates, certificate inventories

### **Trusts Module (`-Modules trusts`)**

**Purpose**: Trust relationship security analysis

**Capabilities**:

- Domain trust enumeration
- Forest trust analysis
- External trust review
- SID history detection
- Trust security assessment

**Output**: Trust relationship maps, SID history findings, trust security recommendations

### **Delegation Module (`-Modules delegation`)**

**Purpose**: Delegation configuration security review

**Capabilities**:

- Unconstrained delegation detection
- Constrained delegation analysis
- Resource-based constrained delegation review
- Delegation vulnerability assessment

**Output**: Delegation findings, security recommendations, configuration analysis

### **Compliance Module (`-Modules compliance`)**

**Purpose**: Security baseline and compliance assessment

**Capabilities**:

- Password policy compliance
- Account lockout policy review
- Audit policy assessment
- Security setting evaluation
- Compliance scoring

**Output**: Compliance scorecards, policy gap analysis, remediation recommendations

## 📁 **Output Structure**

```
AD_Audit_Reports_YYYYMMDD_HHMMSS/
├── 📊 Reports/
│   ├── 🌐 HTML/
│   │   ├── AD_Audit_Dashboard.html          # Interactive security dashboard
│   │   ├── Executive_Summary.html           # High-level findings
│   │   ├── Technical_Details.html           # Detailed technical analysis
│   │   └── Compliance_Report.html           # Compliance assessment
│   ├── 📄 JSON/
│   │   ├── AD_Audit_Complete.json           # Complete audit data
│   │   ├── ldapdomaindump_style.json        # LDAP domain dump
│   │   ├── Security_Findings.json           # Security vulnerabilities
│   │   └── Compliance_Results.json          # Compliance assessment
│   ├── 📈 CSV/
│   │   ├── Users.csv                        # User account data
│   │   ├── Computers.csv                    # Computer account data
│   │   ├── Groups.csv                       # Group information
│   │   ├── Security_Issues.csv              # Security findings
│   │   └── Kerberoastable_Users.csv         # Kerberoastable accounts
│   └── 📋 XML/
│       └── AD_Audit_Report.xml              # Structured XML report
├── 💾 Data/
│   ├── 🔧 Core/
│   │   ├── domain_info.json                 # Domain metadata
│   │   ├── users_raw.json                   # Raw user data
│   │   └── computers_raw.json               # Raw computer data
│   ├── 🛡️ Security/
│   │   ├── vulnerabilities.json             # Security vulnerabilities
│   │   ├── privileged_users.json            # Privileged accounts
│   │   └── security_policies.json           # Security configuration
│   ├── 🎫 Kerberos/
│   │   ├── kerberoastable.json              # Kerberoastable accounts
│   │   ├── asreproastable.json              # ASREPRoastable accounts
│   │   └── kerberos_policy.json             # Kerberos settings
│   ├── 📜 Certificates/
│   │   ├── certificate_authorities.json     # CA information
│   │   ├── certificate_templates.json       # Template analysis
│   │   └── esc_vulnerabilities.json         # ESC findings
│   └── 🤝 Trusts/
│       ├── domain_trusts.json               # Trust relationships
│       └── sid_history.json                 # SID history findings
├── 🛠️ Remediation/
│   ├── 📜 Scripts/
│   │   ├── AD_Security_Remediation.ps1      # Automated fixes
│   │   ├── Disable_Inactive_Users.ps1       # User cleanup
│   │   ├── Fix_Kerberos_Issues.ps1          # Kerberos hardening
│   │   └── Certificate_Cleanup.ps1          # PKI security fixes
│   └── 📖 Guides/
│       ├── Security_Remediation_Guide.md    # Step-by-step fixes
│       ├── Kerberos_Hardening_Guide.md      # Kerberos security
│       ├── PKI_Security_Guide.md            # Certificate services
│       └── Compliance_Implementation.md     # Compliance guidance
├── 🔍 Evidence/
│   ├── 📸 Screenshots/                      # Visual evidence
│   ├── 📝 Logs/
│   │   ├── audit.log                        # Detailed audit log
│   │   ├── errors.log                       # Error tracking
│   │   └── performance.log                  # Performance metrics
│   └── 🗂️ Archives/
│       └── raw_data_backup.zip              # Complete data backup
├── 📋 Executive_Summary.txt                 # Business summary
├── 🔧 Configuration.json                    # Audit configuration
└── 📊 Statistics.json                       # Audit statistics
```

## ⚙️ **Prerequisites**

### **System Requirements**

- **Operating System**: Windows 10/11, Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **Memory**: Minimum 4GB RAM (8GB+ recommended for large environments)
- **Disk Space**: 1GB+ free space for reports and logs
- **Network**: Access to domain controllers on ports 389 (LDAP) and 636 (LDAPS)

### **Permissions Required**

- **Domain User**: Minimum for basic enumeration
- **Domain Admin**: Recommended for comprehensive assessment
- **Enterprise Admin**: Required for forest-level analysis
- **Local Admin**: For advanced certificate and delegation analysis

### **Optional Components**

- **Active Directory PowerShell Module**: Enhanced functionality
- **RSAT Tools**: Additional administrative capabilities
- **Certificate Services Tools**: PKI analysis features

### **PowerShell Modules** _(Auto-detected)_

```powershell
# Check for required modules
Get-Module -ListAvailable ActiveDirectory
Get-WindowsFeature -Name RSAT-AD-PowerShell
```

## 🔒 **Security Considerations**

### **Authentication Security**

- **Use dedicated audit accounts** with minimal required privileges
- **Implement service accounts** for automated assessments
- **Rotate credentials regularly** after assessments
- **Log all audit activities** for compliance tracking

### **Data Protection**

- **Encrypt output files** containing sensitive information
- **Secure transfer methods** for audit reports
- **Implement data retention policies** for audit artifacts
- **Access controls** on audit results and logs

### **Network Security**

- **Use encrypted connections** (LDAPS) when available
- **Monitor network traffic** during assessments
- **Implement network segmentation** for audit activities
- **Rate limiting** to avoid overwhelming domain controllers

### **Operational Security**

```powershell
# Example: Secure credential handling
$securePassword = Read-Host "Enter password" -AsSecureString
$credential = New-Object System.Management.Automation.PSCredential("domain\user", $securePassword)

# Example: Encrypted output
$auditData | ConvertTo-Json | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Set-Content "encrypted_audit.txt"
```

### **Compliance Requirements**

- **Document authorization** before conducting assessments
- **Maintain audit trails** of all activities
- **Follow data handling procedures** per organizational policies
- **Report findings** through established security channels

## 🎛️ **Advanced Configuration**

### **Custom Module Development**

```powershell
# Example: Custom security check module
function Invoke-CustomSecurityCheck {
    Write-Log "🔍 Running custom security checks..." -Level Info
    
    $customResults = @{
        CustomFindings = @()
        RiskScore = 0
    }
    
    # Your custom logic here
    
    $Global:Config.Results.Custom = $customResults
    Write-Log "✅ Custom security check completed" -Level Success
}

# Add to main execution flow
$Global:Config.Modules += 'custom'
```

### **Integration with SIEM/SOAR**

```powershell
# Example: Send results to SIEM
$auditResults = Get-Content "Reports\JSON\AD_Audit_Complete.json" | ConvertFrom-Json

# Send to Splunk
$splunkUri = "https://splunk.company.com:8088/services/collector"
$headers = @{"Authorization" = "Splunk $splunkToken"}
Invoke-RestMethod -Uri $splunkUri -Method Post -Headers $headers -Body ($auditResults | ConvertTo-Json)

# Send to Microsoft Sentinel
$workspaceId = "your-workspace-id"
$sharedKey = "your-shared-key"
Send-LogAnalyticsData -WorkspaceId $workspaceId -SharedKey $sharedKey -Body ($auditResults | ConvertTo-Json) -LogType "ADSecurityAudit"
```

### **Automated Scheduling**

```powershell
# Example: Scheduled task for weekly audits
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\unified-ad-audit.ps1 -SkipPrompts"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2AM
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "Weekly AD Security Audit" -Action $action -Trigger $trigger -Settings $settings
```

## 🚨 **Troubleshooting**

### **Common Issues and Solutions**

#### **Issue**: "Access Denied" errors during enumeration

```powershell
# Solution: Check permissions and use appropriate credentials
$testAccess = Test-ADAuthentication -Credential $credential
if (-not $testAccess) {
    Write-Warning "Insufficient permissions. Ensure audit account has required privileges."
}
```

#### **Issue**: Script execution policy errors

```powershell
# Solution: Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or bypass for single execution
PowerShell.exe -ExecutionPolicy Bypass -File .\unified-ad-audit.ps1
```

#### **Issue**: Module import failures

```powershell
# Solution: Install required modules
Install-WindowsFeature -Name RSAT-AD-PowerShell
Import-Module ActiveDirectory -Force
```

#### **Issue**: Network connectivity problems

```powershell
# Solution: Test connectivity and firewall rules
Test-NetConnection -ComputerName "dc01.corp.local" -Port 389
Test-NetConnection -ComputerName "dc01.corp.local" -Port 636
```

### **Debug Mode**

```powershell
# Enable verbose logging and debug output
.\unified-ad-audit.ps1 -Verbose -Debug -DomainController "dc01.corp.local" -DomainName "corp.local"

# Check log files for detailed error information
Get-Content "$env:TEMP\AD_Audit_Reports_*\audit.log" | Select-String "ERROR"
```

### **Performance Optimization**

```powershell
# Optimize for large environments
.\unified-ad-audit.ps1 `
    -DomainController "dc01.corp.local" `
    -DomainName "corp.local" `
    -Threads 25 `                     # Increase thread count
    -Modules @('core','security') `   # Run fewer modules
    -Format "JSON" `                  # Use faster output format
    -SkipPrompts
```

## 🤝 **Contributing**

We welcome contributions from the security community! Here's how you can help:

### **Ways to Contribute**

- 🐛 **Bug Reports**: Report issues and provide reproduction steps
- 💡 **Feature Requests**: Suggest new modules or capabilities
- 🔧 **Code Contributions**: Submit pull requests with improvements
- 📖 **Documentation**: Improve guides and examples
- 🧪 **Testing**: Test in different environments and provide feedback

### **Development Setup**

```bash
# Fork the repository
git clone https://github.com/yourusername/unified-ad-audit.git
cd unified-ad-audit

# Create feature branch
git checkout -b feature/new-security-module

# Make changes and test
.\unified-ad-audit.ps1 -DomainController "testdc.lab.local" -DomainName "lab.local" -SkipPrompts

# Commit and push
git add .
git commit -m "Add new security module for XYZ analysis"
git push origin feature/new-security-module

# Create pull request
```

### **Code Standards**

- Follow PowerShell best practices and style guidelines
- Include comprehensive error handling
- Add detailed comments and documentation
- Include parameter validation and help text
- Test thoroughly in lab environments

### **Security Disclosure**

For security vulnerabilities in the tool itself:

- Email: ethicalsoup@gmail.com
- Include detailed reproduction steps
- Allow 90 days for responsible disclosure

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](https://claude.ai/chat/LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Unified AD Audit Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 🙏 **Acknowledgments**

- **Microsoft Active Directory Team** - For comprehensive AD documentation
- **PowerShell Community** - For excellent modules and best practices
- **Security Research Community** - For attack techniques and defense strategies
- **Open Source Contributors** - For inspiration and code examples

## 📞 **Support and Contact**

### **Community Support**

- **GitHub Issues**: [Report bugs and request features](https://github.com/yourusername/unified-ad-audit/issues)
- **Discussions**: [Community Q&A and tips](https://github.com/yourusername/unified-ad-audit/discussions)
- **Wiki**: [Additional documentation and guides](https://github.com/yourusername/unified-ad-audit/wiki)

### **Professional Support**

- **Email**: ethicalsoup@gmail.com
- **Documentation**: [Comprehensive guides and API reference](https://docs.yourorganization.com/unified-ad-audit)
- **Training**: Custom training sessions available for enterprise customers

### **Stay Updated**

- ⭐ **Star this repository** to stay notified of updates
- 👀 **Watch releases** for new versions and security updates
- 📢 **Follow on Twitter**: [@ethicalsoup](https://twitter.com/ethicalsoup)

---

## 🔗 **Quick Links**

|Resource|Description|Link|
|---|---|---|
|🚀 **Quick Start Guide**|Get up and running in 5 minutes|[Quick Start](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-quick-start)|
|📖 **Module Documentation**|Detailed module capabilities|[Modules](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-module-documentation)|
|🎯 **Walkthroughs**|Step-by-step usage examples|[Walkthroughs](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-detailed-walkthroughs)|
|🔧 **Troubleshooting**|Common issues and solutions|[Troubleshooting](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-troubleshooting)|
|🤝 **Contributing**|Help improve the project|[Contributing](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-contributing)|
|📄 **License**|Usage terms and conditions|[License](https://claude.ai/chat/9363904c-5449-4c39-a759-23e883ac7755#-license)|

---

**⚠️ Important**: This tool is for authorized security assessments only. Ensure you have proper authorization before running against any Active Directory environment. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

**📊 Project Statistics**: ![GitHub stars](https://img.shields.io/github/stars/yourusername/unified-ad-audit) ![GitHub forks](https://img.shields.io/github/forks/yourusername/unified-ad-audit) ![GitHub issues](https://img.shields.io/github/issues/yourusername/unified-ad-audit) ![GitHub last commit](https://github.com/javalogicuser/remy-AD)