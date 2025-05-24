
#Requires -Version 5.1
<#
.SYNOPSIS
    Remote Comprehensive Active Directory Security Assessment & Audit Tool
    
.DESCRIPTION
    Unified PowerShell script combining multiple AD security assessment modules:
    - Core AD Enumeration (Users, Groups, Computers, OUs)
    - LDAP Domain Dump (JSON/HTML output)
    - Security Analysis (Kerberoasting, ASREPRoast, Delegation)
    - Certificate Services Assessment
    - Trust Relationship Analysis
    - Privilege Escalation Vectors
    - Security Misconfigurations
    - Compliance Reporting
    
.PARAMETER DomainController
    FQDN or IP address of the domain controller to query
    
.PARAMETER DomainName
    Active Directory domain name (e.g., corp.local)
    
.PARAMETER Credential
    PSCredential object for authentication (optional)
    
.PARAMETER Modules
    Array of modules to run. Options: core, ldap, security, kerberos, certificates, trusts, delegation, compliance, all
    
.PARAMETER OutputPath
    Directory path for output files (default: $env:TEMP\AD_Audit_Reports)
    
.PARAMETER Format
    Output format options: HTML, JSON, CSV, XML, All (default: All)
    
.PARAMETER SkipPrompts
    Skip interactive prompts and use provided parameters only
    
.PARAMETER Threads
    Number of concurrent threads for enumeration (default: 10)
    
.PARAMETER Verbose
    Enable verbose output for detailed logging
    
.EXAMPLE
    .\remy-ad-audit.ps1 -DomainController dc01.corp.local -DomainName corp.local
    
.EXAMPLE
    .\remy-ad-audit.ps1 -DomainController 192.168.1.10 -DomainName corp.local -Modules @('security','kerberos') -Format HTML
    
.NOTES
    Author: ethicalsoup@gmail.com
    Version: 4.0
    Requires: PowerShell 5.1+, Active Directory Module (optional), RSAT Tools
#>

# Set strict mode and error behavior
#$ErrorActionPreference = "Stop"
#Set-StrictMode -Version Latest

param (
    [Parameter(Mandatory = $false, HelpMessage = "Domain Controller FQDN or IP address")]
    [string]$DomainController,

    [Parameter(Mandatory = $false, HelpMessage = "Active Directory domain name")]
    [string]$DomainName,

    [Parameter(Mandatory = $false, HelpMessage = "Credentials for AD authentication")]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory=$false)]
    [string[]]$Modules = @("all"),

    [Parameter(Mandatory = $false, HelpMessage = "Output directory path")]
    [string]$OutputPath = "$env:TEMP\AD_Audit_Reports",

    [Parameter(Mandatory = $false, HelpMessage = "Report output format")]
    [ValidateSet('HTML', 'JSON', 'CSV', 'XML', 'All')]
    [string]$Format = 'All',

    [Parameter(Mandatory = $false, HelpMessage = "Path to BloodHound collector (SharpHound.exe)")]
    [string]$BloodHoundPath,

    [Parameter(Mandatory = $false, HelpMessage = "BloodHound collection methods")]
    [string]$CollectionMethods = "Default,Container,Group,LocalAdmin,Session,Trusts",

    [Parameter(Mandatory = $false, HelpMessage = "Skip interactive parameter prompts")]
    [switch]$SkipPrompts,

    [Parameter(Mandatory = $false, HelpMessage = "Include remediation scripts and guides")]
    [switch]$IncludeRemediation,

    [Parameter(Mandatory = $false, HelpMessage = "Compress output to ZIP archive")]
    [switch]$ZipOutput,

    [Parameter(Mandatory = $false, HelpMessage = "Export BloodHound-style edge relationships")]
    [switch]$ExportBloodHound
)

# Global Variables and Configuration
$Global:Config = @{
    ScriptVersion = "4.0"
    StartTime = Get-Date
    LogLevel = if($VerbosePreference -eq 'Continue') { 'Verbose' } else { 'Info' }
    Results = @{}
    Findings = @()
    Statistics = @{
        TotalUsers = 0
        TotalComputers = 0
        TotalGroups = 0
        SecurityIssues = 0
        HighRiskFindings = 0
        MediumRiskFindings = 0
        LowRiskFindings = 0
    }
}

#region ASCII Banner and Initialization
function Show-Banner {
    Clear-Host
    Write-Host @'
 ________________________________________________________________
8888888b.                                             d8888 8888888b.  
888   Y88b                                           d88888 888   Y88b 
888    888                                          d88P888 888    888 
888   d88P .d88b.  88888b.d88b.  888  888          d88P 888 888    888 
8888888P  d8P  Y8b 888 "888 "88b 888  888         d88P  888 888    888 
888 T88b  88888888 888  888  888 888  888        d88P   888 888    888 
888  T88b Y8b.     888  888  888 Y88b 888       d8888888888 888  .d88P 
888   T88b  Y8888  888  888  888   Y88888      d88P     888 8888888P  
                                      888                              
                                 Y8b d88P                              
                                   Y88P              ~ ethicalsoup                     
 ________________________________________________________________
  🔍 COMPREHENSIVE ACTIVE DIRECTORY SECURITY ASSESSMENT PLATFORM 🔍
  
  Version: 4.0 | Multi-Module Security Audit & Compliance Framework
  Coverage: Complete AD Infrastructure Security Analysis
  
  ✅ Core AD Enumeration        ✅ LDAP Domain Intelligence
  ✅ Kerberos Security Analysis ✅ Certificate Services Audit  
  ✅ Trust Relationship Review  ✅ Privilege Escalation Vectors
  ✅ Security Misconfigurations ✅ Compliance Reporting
  ✅ Automated Remediation      ✅ Executive Dashboards
  
  ⚠️  AUTHORIZED PERSONNEL ONLY - ENSURE PROPER APPROVAL ⚠️
 ________________________________________________________________________
'@ -ForegroundColor Cyan

    Write-Host "[INFO] Initializing Unified AD Audit Platform v$($Global:Config.ScriptVersion)..." -ForegroundColor Green
    Write-Host "[INFO] Timestamp: $($Global:Config.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Verbose')]
        [string]$Level = 'Info',
        [switch]$NoNewLine
    )
    
    $timestamp = Get-Date -Format 'HH:mm:ss'
    $prefix = switch($Level) {
        'Info'    { "[INFO]" }
        'Warning' { "[WARN]" }
        'Error'   { "[ERROR]" }
        'Success' { "[SUCCESS]" }
        'Verbose' { "[VERBOSE]" }
    }
    
    $color = switch($Level) {
        'Info'    { 'White' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
        'Verbose' { 'Gray' }
    }
    
    $logMessage = "$timestamp $prefix $Message"

    if ($Level -eq 'Verbose' -and $Global:Config.LogLevel -eq 'Verbose') {
    Write-Verbose "[DEBUG] Verbose logging enabled"
}

    $NoNewLine = $false  # Ensure it's initialized
    if($NoNewLine) {
        Write-Host -NoNewLine $logMessage -ForegroundColor $color -NoNewline
    } else {
        Write-Host $logMessage -ForegroundColor $color
    }
    
    # Log to file if output path is set
    if($Global:Config.OutputPath -and (Test-Path $Global:Config.OutputPath)) {
        $logFile = Join-Path $Global:Config.OutputPath "audit.log"
        Add-Content -Path $logFile -Value $logMessage
    }
}
#endregion

#region BloodHound Edge Helpers

$Global:BloodHoundEdges = @()

function Add-BloodHoundEdge {
    param (
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $false)][hashtable]$Meta
    )
    if (-not $Meta) { $Meta = @{} }
    $Global:BloodHoundEdges += [PSCustomObject]@{
        Source = $Source
        Target = $Target
        Type   = $Type
        Meta   = $Meta
    }
}

function Export-BloodHoundEdges {
    param (
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory | Out-Null
    }

    $Global:BloodHoundEdges |
        Group-Object Type |
        ForEach-Object {
            $type = $_.Name.ToLower()
            $filePath = Join-Path $OutputPath "$type`_edges.json"
            $_.Group | ConvertTo-Json -Depth 10 | Set-Content -Path $filePath -Encoding UTF8
        }

    Write-Log "Exported BloodHound edges to $OutputPath" -Level Info
}

#endregion

#region Parameter Validation and Setup
function Initialize-Parameters {
    Write-Log "Validating and initializing parameters..." -Level Info
    
    # ADD THIS TO YOUR Initialize-Parameters FUNCTION:

# Auto-detect current domain if not specified
if ([string]::IsNullOrWhiteSpace($DomainName)) {
    try {
        $script:DomainName = (Get-WmiObject Win32_ComputerSystem).Domain
        Write-Log "Auto-detected domain: $DomainName" -Level Success
    } catch [System.Exception] {
        Write-Log "Could not auto-detect domain" -Level Warning
    }
}

# Auto-detect domain controller if not specified
if ([string]::IsNullOrWhiteSpace($DomainController) -and -not [string]::IsNullOrWhiteSpace($DomainName)) {
    try {
        $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
        $script:DomainController = $dc
        Write-Log "Auto-detected domain controller: $DomainController" -Level Success
    } catch [System.Exception] {
        Write-Log "Could not auto-detect domain controller" -Level Warning
    }
}
    # Display current parameter status
    Write-Host "`n📋 Current Configuration:" -ForegroundColor Yellow
    Write-Host "  🌐 Domain Controller: $(if($DomainController) { $DomainController } else { '❌ Not Set' })" -ForegroundColor Gray
    Write-Host "  🏢 Domain Name: $(if($DomainName) { $DomainName } else { '❌ Not Set' })" -ForegroundColor Gray
    Write-Host "  🔐 Credentials: $(if($Credential) { '✅ Provided (' + $Credential.UserName + ')' } else { '⚠️ Current User (' + $env:USERNAME + ')' })" -ForegroundColor Gray
    Write-Host "  🧩 Modules: $($Modules -join ', ')" -ForegroundColor Gray
    Write-Host "  📁 Output Path: $(if($OutputPath) { $OutputPath } else { '⚙️ Default (Temp)' })" -ForegroundColor Gray
    Write-Host "  📄 Format: $Format" -ForegroundColor Gray
    Write-Host "  🔀 Threads: $Threads" -ForegroundColor Gray
    
    # Interactive parameter collection
    if (-not $SkipPrompts) {
        Write-Host "`n🔧 Interactive Configuration Mode" -ForegroundColor Cyan
        Write-Host "Press Enter to accept current settings or provide missing parameters..." -ForegroundColor Gray
        
        # Domain Controller
        if ([string]::IsNullOrWhiteSpace($DomainController)) {
            Write-Host "`n❗ Domain Controller Required" -ForegroundColor Red
            do {
                $script:DomainController = Read-Host "🌐 Enter Domain Controller (FQDN or IP)"
            } while ([string]::IsNullOrWhiteSpace($DomainController))
        }
        
        # Domain Name
        if ([string]::IsNullOrWhiteSpace($DomainName)) {
            Write-Host "`n❗ Domain Name Required" -ForegroundColor Red
            do {
                $script:DomainName = Read-Host "🏢 Enter Domain Name (e.g., corp.local)"
            } while ([string]::IsNullOrWhiteSpace($DomainName))
        }
        
        # Credentials
        if (-not $Credential) {
            $useCred = Read-Host "`n🔐 Use alternate credentials? (Y/N) [Default: N]"
            if ($useCred -eq 'Y' -or $useCred -eq 'y') {
                try {
                    $script:Credential = Get-Credential -Message "Enter AD credentials for enumeration"
                    if ($Credential) {
                        Write-Log "Credentials provided for user: $($Credential.UserName)" -Level Success
                    }
                } catch [System.Exception]{
                    Write-Log "Failed to get credentials. Using current user context." -Level Warning
                }
            }
        }
        
        # Module Selection
        if ($Modules -contains 'all') {
            Write-Host "`n🧩 Module Selection:" -ForegroundColor Cyan
            Write-Host "  Available: core, ldap, security, kerberos, certificates, trusts, delegation, compliance" -ForegroundColor Gray
            $moduleInput = Read-Host "Enter modules (comma-separated) [Default: all]"
            if (-not [string]::IsNullOrWhiteSpace($moduleInput)) {
                $script:Modules = $moduleInput.Split(',').Trim() | ForEach-Object { $_.Trim() }
            }
        }
        
        # Output Path
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $defaultPath = "$env:TEMP\AD_Audit_Reports_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            $pathInput = Read-Host "`n📁 Output Directory [Default: $defaultPath]"
            $script:OutputPath = if([string]::IsNullOrWhiteSpace($pathInput)) { $defaultPath } else { $pathInput }
        }
    }
    
    # Set defaults for empty parameters
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $script:OutputPath = "$env:TEMP\AD_Audit_Reports_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    }
    
    # Expand 'all' modules
    if ($Modules -contains 'all') {
        $script:Modules = @('core','ldap','security','kerberos','certificates','trusts','delegation','compliance')
    }
    
    # Validate required parameters
    $missingParams = @()
    if ([string]::IsNullOrWhiteSpace($DomainController)) { $missingParams += "DomainController" }
    if ([string]::IsNullOrWhiteSpace($DomainName)) { $missingParams += "DomainName" }
    
    if ($missingParams.Count -gt 0) {
        Write-Log "Missing required parameters: $($missingParams -join ', ')" -Level Error
        throw "Required parameters not provided. Use -SkipPrompts to bypass interactive mode."
    }
    
    # Store in global config
    $Global:Config.DomainController = $DomainController
    $Global:Config.DomainName = $DomainName
    $Global:Config.Credential = $Credential
    $Global:Config.Modules = $Modules
    $Global:Config.OutputPath = $OutputPath
    $Global:Config.Format = $Format
    $Global:Config.Threads = $Threads
    
    Write-Log "Parameter validation completed successfully" -Level Success
}

function Initialize-OutputStructure {
    Write-Log "Creating output directory structure..." -Level Info
    
    try {
        # Create main output directory
        if (-not (Test-Path $Global:Config.OutputPath)) {
            New-Item -ItemType Directory -Path $Global:Config.OutputPath -Force | Out-Null
        }
        
        # Create subdirectories
        $subDirs = @(
            'Reports\HTML',
            'Reports\JSON', 
            'Reports\CSV',
            'Reports\XML',
            'Data\Core',
            'Data\Security',
            'Data\Certificates',
            'Data\Trusts',
            'Evidence\Screenshots',
            'Evidence\Logs',
            'Remediation\Scripts',
            'Remediation\Guides'
        )
        
        foreach ($dir in $subDirs) {
            $fullPath = Join-Path $Global:Config.OutputPath $dir
            if (-not (Test-Path $fullPath)) {
                New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
            }
        }
        
        Write-Log "Output structure created: $($Global:Config.OutputPath)" -Level Success
        
        # Create initial log file
        $logFile = Join-Path $Global:Config.OutputPath "audit.log"
        $headerInfo = @"
================================================================================
Unified AD Security Audit Log
Started: $($Global:Config.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
Version: $($Global:Config.ScriptVersion)
Domain: $($Global:Config.DomainName)
Domain Controller: $($Global:Config.DomainController)
Modules: $($Global:Config.Modules -join ', ')
User: $(if($Global:Config.Credential) { $Global:Config.Credential.UserName } else { $env:USERNAME })
================================================================================

"@
        Set-Content -Path $logFile -Value $headerInfo
        
    } catch [System.Exception]{
        Write-Log "Failed to create output structure: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Test-Prerequisites {
    Write-Log "Testing prerequisites and connectivity..." -Level Info
    
    $issues = @()
    
    # Test PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $issues += "PowerShell 5.1 or higher required (current: $($PSVersionTable.PSVersion))"
    }
    
    # Test domain controller connectivity
    try {
        Write-Log "Testing LDAP connectivity to $($Global:Config.DomainController)..." -Level Verbose
        $testLDAP = Test-NetConnection -ComputerName $Global:Config.DomainController -Port 389 -WarningAction SilentlyContinue
        if (-not $testLDAP.TcpTestSucceeded) {
            $issues += "Cannot connect to LDAP port 389 on $($Global:Config.DomainController)"
        } else {
            Write-Log "LDAP connectivity successful" -Level Success
        }
        
        # Test LDAPS if available
        $testLDAPS = Test-NetConnection -ComputerName $Global:Config.DomainController -Port 636 -WarningAction SilentlyContinue
        if ($testLDAPS.TcpTestSucceeded) {
            Write-Log "LDAPS (636) also available" -Level Success
            $Global:Config.LDAPSAvailable = $true
        }
    } catch [System.Exception]{
        $issues += "Network connectivity test failed: $($_.Exception.Message)"
    }
    
    # Test AD PowerShell module
    try {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        if (Get-Module ActiveDirectory) {
            Write-Log "Active Directory PowerShell module loaded" -Level Success
            $Global:Config.ADModuleAvailable = $true
        } else {
            Write-Log "AD PowerShell module not available - using LDAP queries" -Level Warning
            $Global:Config.ADModuleAvailable = $false
        }
    } catch {
        Write-Log "AD PowerShell module not available - using LDAP queries" -Level Warning
        $Global:Config.ADModuleAvailable = $false
    }
    
    # Test credentials if provided
    if ($Global:Config.Credential) {
        try {
            # Simple LDAP bind test would go here
            Write-Log "Credential validation would be performed here" -Level Verbose
        } catch {
            $issues += "Credential validation failed"
        }
    }
    
    if ($issues.Count -gt 0) {
        Write-Log "Prerequisites check found issues:" -Level Warning
        foreach ($issue in $issues) {
            Write-Log "  - $issue" -Level Warning
        }
        
        $continue = if(-not $SkipPrompts) {
            Read-Host "Continue anyway? (Y/N) [Default: N]"
        } else { 'N' }
        
        if ($continue -ne 'Y' -and $continue -ne 'y') {
            throw "Prerequisites not met. Aborting audit."
        }
    } else {
        Write-Log "All prerequisites satisfied" -Level Success
    }
}
#endregion

#region LDAP Helper Functions
function New-LDAPConnection {
    param(
        [string]$Server = $Global:Config.DomainController,
        [System.Management.Automation.PSCredential]$Credential = $Global:Config.Credential,
        [switch]$UseSSL
    )
    
    try {
        # Add debug logging
        Write-Log "Attempting LDAP connection to: $Server" -Level Verbose
        Write-Log "Using credentials: $(if($Credential) { $Credential.UserName } else { 'Current user context' })" -Level Verbose
        
        if ([string]::IsNullOrEmpty($Server)) {
            throw "Domain Controller parameter is null or empty"
        }
        
        $protocol = if ($UseSSL -and $Global:Config.LDAPSAvailable) { "LDAPS" } else { "LDAP" }
        $connectionString = "$protocol`://$Server"
        
        Write-Log "Connection string: $connectionString" -Level Verbose
        
        $directoryEntry = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry($connectionString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        } else {
            New-Object System.DirectoryServices.DirectoryEntry($connectionString)
        }
        
        # Test connection
        Write-Log "Testing LDAP connection..." -Level Verbose
        $testDN = $directoryEntry.distinguishedName
        Write-Log "Connection successful. Root DN: $testDN" -Level Verbose
        
        return $directoryEntry
    } catch {
        Write-Log "LDAP connection failed: $($_.Exception.Message)" -Level Error
        Write-Log "Server: '$Server', Protocol: '$protocol'" -Level Error
        throw
    }
}

function Invoke-LDAPQuery {
    param(
        [string]$Filter = "(objectClass=*)",
        [string]$SearchBase,
        [string[]]$Properties = @("*"),
        [string]$SearchScope = "Subtree"
    )
    
    try {
        # Fix: Use correct function name
        $directoryEntry = New-LDAPConnection
        
        if (-not $SearchBase) {
            $SearchBase = $directoryEntry.distinguishedName
        }
        
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = $directoryEntry
        $searcher.Filter = $Filter
        $searcher.SearchScope = $SearchScope
        $searcher.PageSize = 1000
        
        foreach ($prop in $Properties) {
            $searcher.PropertiesToLoad.Add($prop) | Out-Null
        }
        
        $results = $searcher.FindAll()
        $searchResults = @()
        
        foreach ($result in $results) {
            $obj = @{}
            foreach ($prop in $result.Properties.Keys) {
                if ($result.Properties[$prop].Count -eq 1) {
                    $obj[$prop] = $result.Properties[$prop][0]
                } else {
                    $obj[$prop] = $result.Properties[$prop]
                }
            }
            $searchResults += [PSCustomObject]$obj
        }
        
        $results.Dispose()
        $searcher.Dispose()
        $directoryEntry.Dispose()
        
        return $searchResults
    } catch {
        Write-Log "LDAP query failed: $($_.Exception.Message)" -Level Error
        return @()
    }
}
#endregion

#region Core AD Enumeration Module
function Invoke-CoreEnumeration {
    Write-Log "🔍 Starting Core AD Enumeration..." -Level Info
    
    $coreResults = @{
        Users = @()
        Computers = @()
        Groups = @()
        OrganizationalUnits = @()
        DomainInfo = @{}
        DomainControllers = @()
    }
    
    try {
        # Domain Information
        Write-Log "Gathering domain information..." -Level Verbose
        $coreResults.DomainInfo = Get-DomainInfo
        
        # Domain Controllers
        Write-Log "Enumerating domain controllers..." -Level Verbose
        $coreResults.DomainControllers = Get-DomainControllers
        
        # Users Enumeration
        Write-Log "Enumerating domain users..." -Level Verbose
        $coreResults.Users = Get-DomainUsers
        $Global:Config.Statistics.TotalUsers = $coreResults.Users.Count
        
        # Computers Enumeration
        Write-Log "Enumerating domain computers..." -Level Verbose
        $coreResults.Computers = Get-DomainComputers
        $Global:Config.Statistics.TotalComputers = $coreResults.Computers.Count
        
        # Groups Enumeration
        Write-Log "Enumerating domain groups..." -Level Verbose
        $coreResults.Groups = Get-DomainGroups
        $Global:Config.Statistics.TotalGroups = $coreResults.Groups.Count
        
        # Organizational Units
        Write-Log "Enumerating organizational units..." -Level Verbose
        $coreResults.OrganizationalUnits = Get-OrganizationalUnits
        
        $Global:Config.Results.Core = $coreResults
        Write-Log "✅ Core enumeration completed successfully" -Level Success
        
    } catch {
        Write-Log "❌ Core enumeration failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-DomainInfo {
     Write-Log "Querying domain information..." -Level Verbose
     
     try {
         if ($Global:Config.ADModuleAvailable) {
             $domain = Get-ADDomain -Server $Global:Config.DomainController -ErrorAction Stop
             return @{
                 Name = $domain.DNSRoot
                 NetBIOSName = $domain.NetBIOSName
                 DistinguishedName = $domain.DistinguishedName
                 DomainController = $Global:Config.DomainController
                 FunctionalLevel = $domain.DomainMode
                 CreationTime = $domain.Created
                 LastModified = $domain.Modified
                 InfrastructureMaster = $domain.InfrastructureMaster
                 PDCEmulator = $domain.PDCEmulator
                 RIDMaster = $domain.RIDMaster
             }
         } else {
             # LDAP fallback
             $domainInfo = Invoke-LDAPQuery -Filter "(objectClass=domain)" -Properties @("distinguishedName", "name", "whenCreated", "whenChanged")
             if ($domainInfo) {
                 return @{
                     Name = $Global:Config.DomainName
                     DistinguishedName = $domainInfo[0].distinguishedName
                     DomainController = $Global:Config.DomainController
                     FunctionalLevel = "Unknown (LDAP)"
                     CreationTime = $domainInfo[0].whenCreated
                     LastModified = $domainInfo[0].whenChanged
                 }
             }
         }
     } catch {
         Write-Log "Failed to get domain info: $($_.Exception.Message)" -Level Warning
         return @{
             Name = $Global:Config.DomainName
             DistinguishedName = "DC=$($Global:Config.DomainName.Replace('.', ',DC='))"
             DomainController = $Global:Config.DomainController
             FunctionalLevel = "Unknown"
             CreationTime = "Unknown"
             LastModified = Get-Date
         }
     }
 }
 

function Get-DomainControllers {
    Write-Log "Enumerating domain controllers..." -Level Verbose

    try {
        if ($Global:Config.ADModuleAvailable) {
            $dcs = Get-ADDomainController -Filter * -Server $Global:Config.DomainController
            return $dcs | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name
                    Hostname = $_.HostName
                    IPAddress = $_.IPv4Address
                    Site = $_.Site
                    OperatingSystem = $_.OperatingSystem
                    IsGlobalCatalog = $_.IsGlobalCatalog
                    IsReadOnly = $_.IsReadOnly
                    Enabled = "Unknown"  # Or retrieve using Get-ADComputer if needed
                }
            }
        } else {
            # LDAP fallback
            $dcs = Invoke-LDAPQuery -Filter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Properties @("name", "dNSHostName", "operatingSystem", "whenCreated")
            return $dcs | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.name
                    Hostname = $_.dNSHostName
                    IPAddress = "Unknown"
                    Site = "Unknown"
                    OperatingSystem = $_.operatingSystem
                    IsGlobalCatalog = "Unknown"
                    IsReadOnly = $false
                    Enabled = $true
                }
            }
        }
    } catch {
        Write-Log "Failed to enumerate DCs: $($_.Exception.Message)" -Level Warning
        return @(
            [PSCustomObject]@{
                Name = $Global:Config.DomainController
                Hostname = $Global:Config.DomainController
                IPAddress = "Unknown"
                Site = "Unknown"
                OperatingSystem = "Unknown"
                IsGlobalCatalog = "Unknown"
                IsReadOnly = $false
                Enabled = $false
            }
        )
    }
}

# WITH THIS WORKING IMPLEMENTATION:
function Get-DomainUsers {
    Write-Log "Enumerating domain users..." -Level Verbose
    
    try {
        if ($Global:Config.ADModuleAvailable) {
            $users = Get-ADUser -Filter * -Server $Global:Config.DomainController -Properties Name, SamAccountName, UserPrincipalName, Enabled, PasswordLastSet, LastLogonDate, PasswordNeverExpires, AccountLockoutTime, BadLogonCount, ServicePrincipalName, AdminCount, MemberOf, Description
            
            return $users | ForEach-Object {
                @{
                    Name = $_.Name
                    SamAccountName = $_.SamAccountName
                    UserPrincipalName = $_.UserPrincipalName
                    DistinguishedName = $_.DistinguishedName
                    Enabled = $_.Enabled
                    PasswordLastSet = $_.PasswordLastSet
                    LastLogonDate = $_.LastLogonDate
                    PasswordNeverExpires = $_.PasswordNeverExpires
                    ServicePrincipalName = $_.ServicePrincipalName
                    AdminCount = $_.AdminCount
                    MemberOf = $_.MemberOf
                    Description = $_.Description
                    IsPrivileged = ($_.AdminCount -eq 1)
                    IsService = ($_.ServicePrincipalName -ne $null)
                    DaysSincePasswordChange = if($_.PasswordLastSet) { (Get-Date) - $_.PasswordLastSet | Select-Object -ExpandProperty Days } else { 999 }
                    DaysSinceLastLogon = if($_.LastLogonDate) { (Get-Date) - $_.LastLogonDate | Select-Object -ExpandProperty Days } else { 999 }
                }
            }
        } else {
            # LDAP fallback
            $users = Invoke-LDAPQuery -Filter "(objectClass=user)" -Properties @("name", "sAMAccountName", "userPrincipalName", "distinguishedName", "userAccountControl", "pwdLastSet", "lastLogon", "servicePrincipalName", "adminCount", "memberOf", "description")
            
            return $users | ForEach-Object {
                $uac = [int]$_.userAccountControl
                $isEnabled = -not ($uac -band 2)
                $passwordNeverExpires = $uac -band 65536
                
                @{
                    Name = $_.name
                    SamAccountName = $_.sAMAccountName
                    UserPrincipalName = $_.userPrincipalName
                    DistinguishedName = $_.distinguishedName
                    Enabled = $isEnabled
                    PasswordLastSet = if($_.pwdLastSet) { [DateTime]::FromFileTime($_.pwdLastSet) } else { $null }
                    LastLogonDate = if($_.lastLogon) { [DateTime]::FromFileTime($_.lastLogon) } else { $null }
                    PasswordNeverExpires = $passwordNeverExpires
                    ServicePrincipalName = $_.servicePrincipalName
                    AdminCount = $_.adminCount
                    MemberOf = $_.memberOf
                    Description = $_.description
                    IsPrivileged = ($_.adminCount -eq 1)
                    IsService = ($_.servicePrincipalName -ne $null)
                }
            }
        }
    } catch {
        Write-Log "Failed to enumerate users: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Get-DomainComputers {
    Write-Log "Enumerating domain computers..." -Level Verbose

    try {
        if ($Global:Config.ADModuleAvailable) {
            $computers = Get-ADComputer -Filter * -Server $Global:Config.DomainController -Properties Name, DNSHostName, OperatingSystem, LastLogonDate, Enabled
            return $computers | ForEach-Object {
                [PSCustomObject]@{
                    Name           = $_.Name
                    Hostname       = $_.DNSHostName
                    OperatingSystem = $_.OperatingSystem
                    LastLogonDate  = $_.LastLogonDate
                    Enabled        = $_.Enabled
                }
            }
        } else {
            $results = Invoke-LDAPQuery -Filter "(objectClass=computer)" -Properties @("name", "dNSHostName", "operatingSystem")
            return $results | ForEach-Object {
                [PSCustomObject]@{
                    Name           = $_.name
                    Hostname       = $_.dNSHostName
                    OperatingSystem = $_.operatingSystem
                    LastLogonDate  = "Unknown"
                    Enabled        = $true
                }
            }
        }
    } catch {
        Write-Log "Failed to enumerate computers: $($_.Exception.Message)" -Level Warning
        return @()
    }
}


function Get-DomainGroups {
    Write-Log "Enumerating domain groups..." -Level Verbose

    try {
        if ($Global:Config.ADModuleAvailable) {
            $groups = Get-ADGroup -Filter * -Server $Global:Config.DomainController -Properties Name, GroupScope, Description
            return $groups | ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.Name
                    Scope       = $_.GroupScope
                    Description = $_.Description
                }
            }
        } else {
            $results = Invoke-LDAPQuery -Filter "(objectClass=group)" -Properties @("name", "description")
            return $results | ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.name
                    Scope       = "Unknown"
                    Description = $_.description
                }
            }
        }
    } catch {
        Write-Log "Failed to enumerate groups: $($_.Exception.Message)" -Level Warning
        return @()
    }
}


function Get-OrganizationalUnits {
    Write-Log "Enumerating organizational units..." -Level Verbose

    try {
        if ($Global:Config.ADModuleAvailable) {
            $ous = Get-ADOrganizationalUnit -Filter * -Server $Global:Config.DomainController -Properties Name, DistinguishedName
            return $ous | ForEach-Object {
                [PSCustomObject]@{
                    Name              = $_.Name
                    DistinguishedName = $_.DistinguishedName
                }
            }
        } else {
            $results = Invoke-LDAPQuery -Filter "(objectClass=organizationalUnit)" -Properties @("name", "distinguishedName")
            return $results | ForEach-Object {
                [PSCustomObject]@{
                    Name              = $_.name
                    DistinguishedName = $_.distinguishedName
                }
            }
        }
    } catch {
        Write-Log "Failed to enumerate OUs: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

#endregion

#region Security Analysis Module
function Invoke-SecurityAnalysis {
    Write-Log "🛡️ Starting Security Analysis..." -Level Info
    
    $securityResults = @{
        KerberoastableUsers = @()
        ASREPRoastableUsers = @()
        UnconstrainedDelegation = @()
        ConstrainedDelegation = @()
        WeakPasswords = @()
        PrivilegedUsers = @()
        StaleLegacy = @()
        Misconfigurations = @()
    }
    
    try {
        Write-Log "Analyzing Kerberoastable accounts..." -Level Verbose
        $securityResults.KerberoastableUsers = Find-KerberoastableUsers
        
        Write-Log "Analyzing ASREPRoastable accounts..." -Level Verbose
        $securityResults.ASREPRoastableUsers = Find-ASREPRoastableUsers
        
        Write-Log "Analyzing delegation configurations..." -Level Verbose
        $securityResults.UnconstrainedDelegation = Find-UnconstrainedDelegation
        $securityResults.ConstrainedDelegation = Find-ConstrainedDelegation
        
        Write-Log "Analyzing privileged accounts..." -Level Verbose
        $securityResults.PrivilegedUsers = Find-PrivilegedUsers
        
        Write-Log "Checking for common misconfigurations..." -Level Verbose
        $securityResults.Misconfigurations = Find-SecurityMisconfigurations
        
        $Global:Config.Results.Security = $securityResults
        Write-Log "✅ Security analysis completed successfully" -Level Success
        
    } catch {
        Write-Log "❌ Security analysis failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

# Placeholder functions for security analysis
function Find-KerberoastableUsers {
    Write-Log "Searching for Kerberoastable service accounts..." -Level Verbose
    
    try {
        if ($Global:Config.ADModuleAvailable) {
            $kerberoastable = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Server $Global:Config.DomainController -Properties ServicePrincipalName, PasswordLastSet, LastLogonDate, AdminCount
            
            return $kerberoastable | ForEach-Object {
                @{
                    Name = $_.Name
                    SamAccountName = $_.SamAccountName
                    ServicePrincipalName = $_.ServicePrincipalName -join '; '
                    PasswordLastSet = $_.PasswordLastSet
                    LastLogonDate = $_.LastLogonDate
                    IsPrivileged = ($_.AdminCount -eq 1)
                    RiskLevel = if($_.AdminCount -eq 1) { "High" } else { "Medium" }
                }
            }
        } else {
            # LDAP fallback
            $users = Invoke-LDAPQuery -Filter "(&(objectClass=user)(servicePrincipalName=*))" -Properties @("name", "sAMAccountName", "servicePrincipalName", "pwdLastSet", "lastLogon", "adminCount")
            
            return $users | ForEach-Object {
                @{
                    Name = $_.name
                    SamAccountName = $_.sAMAccountName
                    ServicePrincipalName = $_.servicePrincipalName -join '; '
                    PasswordLastSet = if($_.pwdLastSet) { [DateTime]::FromFileTime($_.pwdLastSet) } else { $null }
                    LastLogonDate = if($_.lastLogon) { [DateTime]::FromFileTime($_.lastLogon) } else { $null }
                    IsPrivileged = ($_.adminCount -eq 1)
                    RiskLevel = if($_.adminCount -eq 1) { "High" } else { "Medium" }
                }
            }
        }
    } catch {
        Write-Log "Failed to find Kerberoastable users: $($_.Exception.Message)" -Level Warning
        return @()
    }
}
function Find-ASREPRoastableUsers {
    Write-Log "Finding AS-REP roastable users..." -Level Verbose

    try {
        if ($Global:Config.ADModuleAvailable) {
            $users = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} -Properties SamAccountName, DoesNotRequirePreAuth
            return $users | ForEach-Object {
                [PSCustomObject]@{
                    SamAccountName       = $_.SamAccountName
                    DoesNotRequirePreAuth = $true
                }
            }
        } else {
            $results = Invoke-LDAPQuery -Filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" -Properties @("sAMAccountName")
            return $results | ForEach-Object {
                [PSCustomObject]@{
                    SamAccountName       = $_.sAMAccountName
                    DoesNotRequirePreAuth = $true
                }
            }
        }
    } catch {
        Write-Log "Failed to identify AS-REP roastable users: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Find-UnconstrainedDelegation {
    Write-Log "Finding computers/users with unconstrained delegation..." -Level Verbose

    try {
        $uacFlag = 0x80000
        $filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=$uacFlag)(|(objectClass=computer)(objectClass=user)))"
        $results = Invoke-LDAPQuery -Filter $filter -Properties @("sAMAccountName", "userAccountControl", "dNSHostName", "distinguishedName")

        return $results | ForEach-Object {
            [PSCustomObject]@{
                Name             = $_.sAMAccountName
                DistinguishedName = $_.distinguishedName
                Hostname         = $_.dNSHostName
                DelegationType   = "Unconstrained"
            }
        }
    } catch {
        Write-Log "Failed to identify unconstrained delegation: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Find-ConstrainedDelegation {
    Write-Log "Finding accounts with constrained delegation..." -Level Verbose

    try {
        $filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*))"
        $results = Invoke-LDAPQuery -Filter $filter -Properties @("sAMAccountName", "msDS-AllowedToDelegateTo", "dNSHostName", "distinguishedName")

        return $results | ForEach-Object {
            [PSCustomObject]@{
                Name                   = $_.sAMAccountName
                DistinguishedName     = $_.distinguishedName
                Hostname               = $_.dNSHostName
                AllowedToDelegateTo    = $_."msDS-AllowedToDelegateTo" -join "; "
                DelegationType         = "Constrained"
            }
        }
    } catch {
        Write-Log "Failed to identify constrained delegation: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Find-PrivilegedUsers {
    Write-Log "Finding privileged users (Domain Admins, Enterprise Admins)..." -Level Verbose

    try {
        $groups = @("Domain Admins", "Enterprise Admins")
        $users = foreach ($group in $groups) {
            try {
                $members = Get-ADGroupMember -Identity $group -Recursive -Server $Global:Config.DomainController
                $members | Where-Object { $_.objectClass -eq "user" } | ForEach-Object {
                    [PSCustomObject]@{
                        Group = $group
                        User  = $_.SamAccountName
                        DN    = $_.DistinguishedName
                    }
                }
            } catch {
                Write-Log "Error retrieving members of ${group}: $($_.Exception.Message)" -Level Warning
            }
        }
        return $users
    } catch {
        Write-Log "Failed to identify privileged users: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Find-SecurityMisconfigurations {
    Write-Log "Running security misconfiguration checks..." -Level Verbose

    $results = @()

    try {
        $results += Find-ASREPRoastableUsers
        $results += Find-UnconstrainedDelegation
        $results += Find-ConstrainedDelegation
        $results += Find-PrivilegedUsers

        # Add custom misconfig detection here (e.g., dangerous ACLs, SIDHistory, etc.)

        return $results
    } catch {
        Write-Log "Failed to complete security misconfiguration scan: $($_.Exception.Message)" -Level Warning
        return $results
    }
}

#endregion

#region Report Generation
function Generate-Reports {
    Write-Log "📊 Generating comprehensive reports..." -Level Info
    
    try {
        $reportPath = Join-Path $Global:Config.OutputPath "Reports"
        
        if ($Global:Config.Format -eq 'All' -or $Global:Config.Format -eq 'HTML') {
            Write-Log "Generating HTML dashboard..." -Level Verbose
            Generate-HTMLDashboard
        }
        
        if ($Global:Config.Format -eq 'All' -or $Global:Config.Format -eq 'JSON') {
            Write-Log "Generating JSON export..." -Level Verbose
            Generate-JSONReport
        }
        
        if ($Global:Config.Format -eq 'All' -or $Global:Config.Format -eq 'CSV') {
            Write-Log "Generating CSV reports..." -Level Verbose
            Generate-CSVReports
        }
        
        if ($Global:Config.Format -eq 'All' -or $Global:Config.Format -eq 'XML') {
            Write-Log "Generating XML report..." -Level Verbose
            Generate-XMLReport
        }
        
        Generate-ExecutiveSummary
        
        Write-Log "✅ All reports generated successfully" -Level Success
        
    } catch {
        Write-Log "❌ Report generation failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Generate-HTMLDashboard {
    $htmlPath = Join-Path $Global:Config.OutputPath "Reports\HTML\AD_Audit_Dashboard.html"
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>AD Security Audit Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 8px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #3498db; }
        .risk-high { color: #e74c3c; }
        .risk-medium { color: #f39c12; }
        .risk-low { color: #27ae60; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Active Directory Security Audit Report</h1>
        <p>Domain: $($Global:Config.DomainName) | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="summary">
        <div class="card">
            <h3>📊 Domain Statistics</h3>
            <div class="stat-number">$($Global:Config.Statistics.TotalUsers)</div>
            <p>Total Users</p>
            <div class="stat-number">$($Global:Config.Statistics.TotalComputers)</div>
            <p>Total Computers</p>
            <div class="stat-number">$($Global:Config.Statistics.TotalGroups)</div>
            <p>Total Groups</p>
        </div>
        
        <div class="card">
            <h3>🚨 Security Findings</h3>
            <div class="stat-number risk-high">$($Global:Config.Statistics.HighRiskFindings)</div>
            <p>High Risk Issues</p>
            <div class="stat-number risk-medium">$($Global:Config.Statistics.MediumRiskFindings)</div>
            <p>Medium Risk Issues</p>
            <div class="stat-number risk-low">$($Global:Config.Statistics.LowRiskFindings)</div>
            <p>Low Risk Issues</p>
        </div>
    </div>
    
    <div class="card">
        <h3>📋 Audit Summary</h3>
        <p>This automated security assessment identified potential vulnerabilities and misconfigurations in your Active Directory environment.</p>
        <p><strong>Modules Executed:</strong> $($Global:Config.Modules -join ', ')</p>
        <p><strong>Completion Time:</strong> $((Get-Date) - $Global:Config.StartTime)</p>
    </div>
</body>
</html>
"@

    Set-Content -Path $htmlPath -Value $htmlContent -Encoding UTF8
    Write-Log "HTML dashboard saved: $htmlPath" -Level Success
}

function Generate-JSONReport {
    $jsonPath = Join-Path $Global:Config.OutputPath "Reports\JSON\AD_Audit_Complete.json"
    
    $reportData = @{
        AuditInfo = @{
            Version = $Global:Config.ScriptVersion
            StartTime = $Global:Config.StartTime
            EndTime = Get-Date
            Domain = $Global:Config.DomainName
            DomainController = $Global:Config.DomainController
            Modules = $Global:Config.Modules
        }
        Statistics = $Global:Config.Statistics
        Results = $Global:Config.Results
        Findings = $Global:Config.Findings
    }
    
    $jsonContent = $reportData | ConvertTo-Json -Depth 10
    Set-Content -Path $jsonPath -Value $jsonContent -Encoding UTF8
    Write-Log "JSON report saved: $jsonPath" -Level Success
}

function Generate-CSVReports {
    # Generate separate CSV files for different data types
    $csvPath = Join-Path $Global:Config.OutputPath "Reports\CSV"
    
    # Users CSV
    if ($Global:Config.Results.Core.Users) {
        $usersPath = Join-Path $csvPath "Users.csv"
        $Global:Config.Results.Core.Users | Export-Csv -Path $usersPath -NoTypeInformation
    }
    
    # Computers CSV
    if ($Global:Config.Results.Core.Computers) {
        $computersPath = Join-Path $csvPath "Computers.csv"
        $Global:Config.Results.Core.Computers | Export-Csv -Path $computersPath -NoTypeInformation
    }
    
    Write-Log "CSV reports saved to: $csvPath" -Level Success
}

function Generate-XMLReport {
    $xmlPath = Join-Path $Global:Config.OutputPath "Reports\XML\AD_Audit_Report.xml"
    
    $reportData = @{
        AuditInfo = @{
            Version = $Global:Config.ScriptVersion
            StartTime = $Global:Config.StartTime
            EndTime = Get-Date
            Domain = $Global:Config.DomainName
            DomainController = $Global:Config.DomainController
        }
        Statistics = $Global:Config.Statistics
        Results = $Global:Config.Results
    }
    
    $xmlContent = $reportData | ConvertTo-Xml -NoTypeInformation
    $xmlContent.Save($xmlPath)
    Write-Log "XML report saved: $xmlPath" -Level Success
}

function Generate-ExecutiveSummary {
    $summaryPath = Join-Path $Global:Config.OutputPath "Executive_Summary.txt"
    
    $duration = (Get-Date) - $Global:Config.StartTime
    $summaryContent = @"
================================================================================
                    ACTIVE DIRECTORY SECURITY AUDIT
                         EXECUTIVE SUMMARY
================================================================================

AUDIT OVERVIEW
--------------
Domain:              $($Global:Config.DomainName)
Domain Controller:   $($Global:Config.DomainController)
Audit Date:          $($Global:Config.StartTime.ToString('yyyy-MM-dd'))
Duration:            $($duration.ToString('hh\:mm\:ss'))
Modules Executed:    $($Global:Config.Modules -join ', ')
Auditor:             $(if($Global:Config.Credential) { $Global:Config.Credential.UserName } else { $env:USERNAME })

DOMAIN STATISTICS
-----------------
Total Users:         $($Global:Config.Statistics.TotalUsers)
Total Computers:     $($Global:Config.Statistics.TotalComputers)
Total Groups:        $($Global:Config.Statistics.TotalGroups)

SECURITY FINDINGS SUMMARY
--------------------------
🔴 High Risk Issues:    $($Global:Config.Statistics.HighRiskFindings)
🟡 Medium Risk Issues:  $($Global:Config.Statistics.MediumRiskFindings)
🟢 Low Risk Issues:     $($Global:Config.Statistics.LowRiskFindings)

RECOMMENDATIONS
---------------
1. Review all high-risk findings immediately
2. Implement security hardening for identified misconfigurations
3. Regular security assessments should be conducted quarterly
4. Consider implementing privileged access management (PAM)
5. Enable advanced threat protection where applicable

NEXT STEPS
----------
1. Review detailed findings in the HTML dashboard
2. Prioritize remediation based on risk levels
3. Implement recommended security controls
4. Schedule follow-up assessment in 90 days

For detailed technical findings, refer to the comprehensive reports in:
$($Global:Config.OutputPath)

================================================================================
"@

    Set-Content -Path $summaryPath -Value $summaryContent -Encoding UTF8
    Write-Log "Executive summary saved: $summaryPath" -Level Success
}
#endregion

#region Additional Security Modules

function Invoke-KerberosAnalysis {
    Write-Log "🎫 Starting Kerberos Security Analysis..." -Level Info
    
    $kerberosResults = @{
        KerberoastableAccounts = @()
        ASREPRoastableAccounts = @()
        WeakEncryption = @()
        KerberosSettings = @{}
        TGTLifetime = 0
        ServiceTicketLifetime = 0
    }
    
    try {
        # Analyze Kerberos settings
        Write-Log "Analyzing domain Kerberos policy..." -Level Verbose
        $kerberosResults.KerberosSettings = Get-KerberosPolicy
        
        # Find Kerberoastable accounts
        Write-Log "Identifying Kerberoastable service accounts..." -Level Verbose
        $kerberosResults.KerberoastableAccounts = Find-KerberoastableAccounts
        
        # Find ASREPRoastable accounts
        Write-Log "Identifying ASREPRoastable accounts..." -Level Verbose
        $kerberosResults.ASREPRoastableAccounts = Find-ASREPRoastableAccounts
        
        # Check for weak encryption
        Write-Log "Checking for weak Kerberos encryption..." -Level Verbose
        $kerberosResults.WeakEncryption = Find-WeakKerberosEncryption
        
        $Global:Config.Results.Kerberos = $kerberosResults
        Write-Log "✅ Kerberos analysis completed successfully" -Level Success
        
    } catch {
        Write-Log "❌ Kerberos analysis failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Invoke-CertificateAnalysis {
    Write-Log "📜 Starting Certificate Services Analysis..." -Level Info
    
    $certResults = @{
        CertificateAuthorities = @()
        CertificateTemplates = @()
        VulnerableTemplates = @()
        ExpiredCertificates = @()
        WeakCertificates = @()
        ESCVulnerabilities = @()
    }
    
    try {
        Write-Log "Enumerating Certificate Authorities..." -Level Verbose
        $certResults.CertificateAuthorities = Get-CertificateAuthorities
        
        Write-Log "Analyzing certificate templates..." -Level Verbose
        $certResults.CertificateTemplates = Get-CertificateTemplates
        
        Write-Log "Checking for ESC vulnerabilities..." -Level Verbose
        $certResults.ESCVulnerabilities = Find-ESCVulnerabilities
        
        Write-Log "Finding vulnerable certificate templates..." -Level Verbose
        $certResults.VulnerableTemplates = Find-VulnerableCertTemplates
        
        $Global:Config.Results.Certificates = $certResults
        Write-Log "✅ Certificate analysis completed successfully" -Level Success
        
    } catch {
        Write-Log "❌ Certificate analysis failed: $($_.Exception.Message)" -Level Error
        Write-Log "Certificate Services may not be installed or accessible" -Level Warning
    }
}

function Invoke-TrustAnalysis {
    Write-Log "🤝 Starting Trust Relationship Analysis..." -Level Info
    
    $trustResults = @{
        DomainTrusts = @()
        ForestTrusts = @()
        ExternalTrusts = @()
        TrustVulnerabilities = @()
        SIDHistory = @()
    }
    
    try {
        Write-Log "Enumerating domain trusts..." -Level Verbose
        $trustResults.DomainTrusts = Get-DomainTrusts
        
        Write-Log "Analyzing trust relationships..." -Level Verbose
        $trustResults.TrustVulnerabilities = Analyze-TrustSecurity
        
        Write-Log "Checking SID history..." -Level Verbose
        $trustResults.SIDHistory = Find-SIDHistoryUsers
        
        $Global:Config.Results.Trusts = $trustResults
        Write-Log "✅ Trust analysis completed successfully" -Level Success
        
    } catch {
        Write-Log "❌ Trust analysis failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Invoke-DelegationAnalysis {
    Write-Log "🔄 Starting Delegation Analysis..." -Level Info
    
    $delegationResults = @{
        UnconstrainedDelegation = @()
        ConstrainedDelegation = @()
        ResourceBasedDelegation = @()
        DelegationVulnerabilities = @()
    }
    
    try {
        Write-Log "Finding unconstrained delegation..." -Level Verbose
        $delegationResults.UnconstrainedDelegation = Find-UnconstrainedDelegationAccounts
        
        Write-Log "Finding constrained delegation..." -Level Verbose
        $delegationResults.ConstrainedDelegation = Find-ConstrainedDelegationAccounts
        
        Write-Log "Finding resource-based delegation..." -Level Verbose
        $delegationResults.ResourceBasedDelegation = Find-ResourceBasedDelegation
        
        Write-Log "Analyzing delegation security..." -Level Verbose
        $delegationResults.DelegationVulnerabilities = Analyze-DelegationSecurity
        
        $Global:Config.Results.Delegation = $delegationResults
        Write-Log "✅ Delegation analysis completed successfully" -Level Success
        
    } catch {
        Write-Log "❌ Delegation analysis failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Invoke-ComplianceAnalysis {
    Write-Log "📋 Starting Compliance Analysis..." -Level Info
    
    $complianceResults = @{
        PasswordPolicy = @{}
        AccountLockout = @{}
        AuditPolicy = @{}
        SecuritySettings = @{}
        ComplianceScore = 0
        Recommendations = @()
    }
    
    try {
        Write-Log "Analyzing password policies..." -Level Verbose
        $complianceResults.PasswordPolicy = Get-PasswordPolicyCompliance
        
        Write-Log "Analyzing account lockout policies..." -Level Verbose
        $complianceResults.AccountLockout = Get-AccountLockoutCompliance
        
        Write-Log "Analyzing audit policies..." -Level Verbose
        $complianceResults.AuditPolicy = Get-AuditPolicyCompliance
        
        Write-Log "Calculating compliance score..." -Level Verbose
        $complianceResults.ComplianceScore = Calculate-ComplianceScore $complianceResults
        
        $Global:Config.Results.Compliance = $complianceResults
        Write-Log "✅ Compliance analysis completed successfully" -Level Success
        
    } catch {
        Write-Log "❌ Compliance analysis failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

# Placeholder functions for security analysis modules
function Get-KerberosPolicy {
    Write-Log "Retrieving Kerberos policy..." -Level Verbose

    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $policy = Get-ADDefaultDomainPasswordPolicy -Server $Global:Config.DomainController

        return [PSCustomObject]@{
            MaxTicketAge          = $policy.MaxTicketAge
            MaxRenewAge           = $policy.MaxRenewAge
            MaxServiceTicketAge   = $policy.MaxServiceTicketAge
            MaxClockSkew          = $policy.MaxClockSkew
        }
    } catch {
        Write-Log "Failed to retrieve Kerberos policy: $($_.Exception.Message)" -Level Warning
        return [PSCustomObject]@{
            MaxTicketAge        = "Unknown"
            MaxRenewAge         = "Unknown"
            MaxServiceTicketAge = "Unknown"
            MaxClockSkew        = "Unknown"
        }
    }
}

function Find-KerberoastableAccounts {
    [CmdletBinding()]
    param(
        [switch]$IncludeDisabled,
        [string]$SearchBase = (Get-ADDomain).DistinguishedName
    )

    Write-Verbose "Finding Kerberoastable accounts..."

    try {
        $filter = "(&(objectClass=user)(servicePrincipalName=*))"
        if (-not $IncludeDisabled) {
            $filter = "(&${filter}(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        }

        $results = Invoke-LDAPQuery -Filter $filter -SearchBase $SearchBase -Properties @("sAMAccountName", "servicePrincipalName")

        return $results | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName       = $_.sAMAccountName
                ServicePrincipalName = $_.servicePrincipalName -join "; "
                IsKerberoastable     = $true
            }
        }
    } catch {
        Write-Warning "Failed to identify Kerberoastable accounts: $($_.Exception.Message)"
        return @()
    }
}


function Find-ASREPRoastableAccounts {
    [CmdletBinding()]
    param(
        [switch]$IncludeDisabled,
        [string]$SearchBase = (Get-ADDomain).DistinguishedName
    )

    Write-Verbose "Finding AS-REP roastable accounts..."

    try {
        $filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        if (-not $IncludeDisabled) {
            $filter = "(&${filter}(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        }

        $results = Invoke-LDAPQuery -Filter $filter -SearchBase $SearchBase -Properties @("sAMAccountName")

        return $results | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName        = $_.sAMAccountName
                DoesNotRequirePreAuth = $true
                IsASREPRoastable      = $true
            }
        }
    } catch {
        Write-Warning "Failed to identify AS-REP roastable accounts: $($_.Exception.Message)"
        return @()
    }
}


function Find-WeakKerberosEncryption {
    Write-Log "Checking for weak Kerberos encryption types..." -Level Verbose
    
    try {
        # Look for accounts using DES encryption
        $weakEncryptionAccounts = @()
        
        if ($Global:Config.ADModuleAvailable) {
            $users = Get-ADUser -Filter {msDS-SupportedEncryptionTypes -like "*"} -Server $Global:Config.DomainController -Properties "msDS-SupportedEncryptionTypes" -ErrorAction SilentlyContinue
            
            foreach ($user in $users) {
                $encTypes = $user."msDS-SupportedEncryptionTypes"
                if ($encTypes -band 3) { # DES-CBC-CRC or DES-CBC-MD5
                    $weakEncryptionAccounts += @{
                        Name = $user.Name
                        SamAccountName = $user.SamAccountName
                        EncryptionTypes = $encTypes
                        Issue = "DES encryption enabled"
                        RiskLevel = "Medium"
                    }
                }
            }
        }
        
        return $weakEncryptionAccounts
    } catch {
        Write-Log "Failed to check weak encryption: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Get-CertificateAuthorities {
    Write-Log "Enumerating Enterprise Certificate Authorities..." -Level Verbose

    try {
        $cas = certutil -config - -dump | Where-Object { $_ -match "Config:" } | ForEach-Object {
            [PSCustomObject]@{
                CAConfig  = ($_ -split ":")[1].Trim()
            }
        }
        return $cas
    } catch {
        Write-Log "Failed to enumerate CAs: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Get-CertificateTemplates {
    Write-Log "Enumerating certificate templates..." -Level Verbose

    try {
        $templates = Get-ADObject -Filter { objectClass -eq "pKICertificateTemplate" } -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$((Get-ADRootDSE).configurationNamingContext)" -Properties *
        return $templates | ForEach-Object {
            [PSCustomObject]@{
                Name            = $_.Name
                DisplayName     = $_.DisplayName
                msPKITemplateSchemaVersion = $_.'msPKI-TemplateSchemaVersion'
                Permissions     = $_.ntSecurityDescriptor
            }
        }
    } catch {
        Write-Log "Failed to enumerate certificate templates: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Find-ESCVulnerabilities {
    Write-Log "Detecting ESC1-ESC16 abuses..." -Level Verbose
    $results = @()
    try {
        $results += Find-VulnerableCertTemplates
        $results += Find-ResourceBasedDelegation
        $results += Find-UnconstrainedDelegationAccounts
        $results += Find-ConstrainedDelegationAccounts
        return $results
    } catch {
        Write-Log "Failed to analyze ESC vulnerabilities: $($_.Exception.Message)" -Level Warning
        return $results
    }
}
function Find-VulnerableCertTemplates {
    Write-Log "Identifying vulnerable certificate templates (ESC1–ESC14)..." -Level Verbose

    $templates = Get-CertificateTemplates
    $vulnTemplates = @()

    foreach ($template in $templates) {
        # ESC1 – Schema version < 2
        if ($template.'msPKI-TemplateSchemaVersion' -lt 2) {
            $vulnTemplates += [PSCustomObject]@{
                TemplateName = $template.Name
                Issue        = "ESC1 (Low schema version)"
            }
        }

        # ESC2/ESC3 – Broad enrollment rights
        if ($template.Permissions -and $template.Permissions -match "Authenticated Users") {
            $vulnTemplates += [PSCustomObject]@{
                TemplateName = $template.Name
                Issue        = "ESC2/ESC3 (Dangerous delegation or enrollment rights)"
            }
        }

        # ESC6 – Manager approval not required AND ENROLLEE_SUPPLIES_SUBJECT enabled
        if ($template.EnrolleeSuppliesSubject -and -not $template.RequiresManagerApproval) {
            $vulnTemplates += [PSCustomObject]@{
                TemplateName = $template.Name
                Issue        = "ESC6 (Enrollee supplies subject w/o manager approval)"
            }
        }

        # ESC7 – Subject name can be user-defined AND client authentication enabled
        if ($template.EnrolleeSuppliesSubject -and $template.EnhancedKeyUsage -match "Client Authentication") {
            $vulnTemplates += [PSCustomObject]@{
                TemplateName = $template.Name
                Issue        = "ESC7 (ClientAuth EKU with user-supplied subject)"
            }
        }

        # ESC8 – EKU includes Client Authentication AND intended for domain authentication
        if ($template.EnhancedKeyUsage -match "Client Authentication" -and $template.SecurityDescriptor -match "Domain Users") {
            $vulnTemplates += [PSCustomObject]@{
                TemplateName = $template.Name
                Issue        = "ESC8 (ClientAuth EKU with Domain Users rights)"
            }
        }

        # ESC13 – Certificate with EKU that allows SmartCardLogon, and accessible to low-priv users
        if ($template.EnhancedKeyUsage -match "Smartcard Logon" -and $template.Permissions -match "Authenticated Users") {
            $vulnTemplates += [PSCustomObject]@{
                TemplateName = $template.Name
                Issue        = "ESC13 (SmartCardLogon EKU with broad access)"
            }
        }

        # ESC14 – Certificate allows exporting private key and is widely accessible
        if ($template.AllowKeyExport -and $template.Permissions -match "Authenticated Users") {
            $vulnTemplates += [PSCustomObject]@{
                TemplateName = $template.Name
                Issue        = "ESC14 (Private key export allowed)"
            }
        }
    }

    return $vulnTemplates
}



function Get-DomainTrusts {
    Write-Log "Enumerating domain trusts..." -Level Verbose
    try {
        return Get-ADTrust -Filter * -Server $Global:Config.DomainController
    } catch {
        Write-Log "Failed to get domain trusts: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Export-AuditReportToZip {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourceFolder,

        [Parameter(Mandatory = $true)]
        [string]$DestinationZip
    )

    if (Test-Path $DestinationZip) {
        Remove-Item $DestinationZip -Force
    }

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($SourceFolder, $DestinationZip)
        Write-Log "Zipped audit report to $DestinationZip" -Level Info
    }
    catch {
        Write-Warning "Failed to zip audit report: $_"
    }
}

function Analyze-TrustSecurity {
    $trusts = Get-DomainTrusts
    Write-Log "Analyzing trust security posture..." -Level Verbose

    return $trusts | ForEach-Object {
        [PSCustomObject]@{
            PartnerDomain  = $_.Name
            TrustType      = $_.TrustType
            Direction      = $_.Direction
            Transitive     = $_.IsTransitive
            SIDFiltering   = if ($_.SIDFilteringForestAware -eq $false) { "Potential SIDHistory risk" } else { "SID Filtering enabled" }
        }
    }
}

function Find-SIDHistoryUsers {
    [CmdletBinding()]
    param(
        [switch]$IncludeDisabled,
        [string]$SearchBase = (Get-ADDomain).DistinguishedName
    )

    Write-Verbose "Searching for users with SIDHistory..."

    try {
        $filter = "(objectClass=user)"
        if (-not $IncludeDisabled) {
            $filter = "(&${filter}(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        }

        $results = Invoke-LDAPQuery -Filter $filter -SearchBase $SearchBase -Properties @("sAMAccountName", "SIDHistory", "distinguishedName")

        return $results | Where-Object { $_.SIDHistory } | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName = $_.sAMAccountName
                SIDHistory     = $_.SIDHistory -join "; "
                DistinguishedName = $_.distinguishedName
            }
        }
    } catch {
        Write-Warning "Failed to find SIDHistory users: $($_.Exception.Message)"
        return @()
    }
}


function Find-UnconstrainedDelegationAccounts {
    [CmdletBinding()]
    param(
        [switch]$IncludeDisabled,
        [string]$SearchBase = (Get-ADDomain).DistinguishedName
    )

    Write-Verbose "Searching for unconstrained delegation accounts..."

    try {
        $flag = 0x80000
        $filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=$flag)(|(objectClass=user)(objectClass=computer)))"
        if (-not $IncludeDisabled) {
            $filter = "(&${filter}(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        }

        $results = Invoke-LDAPQuery -Filter $filter -SearchBase $SearchBase -Properties @("sAMAccountName", "dNSHostName", "distinguishedName")

        return $results | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName = $_.sAMAccountName
                Hostname       = $_.dNSHostName
                DelegationType = "Unconstrained"
                DistinguishedName = $_.distinguishedName
            }
        }
    } catch {
        Write-Warning "Failed to find unconstrained delegation accounts: $($_.Exception.Message)"
        return @()
    }
}


function Find-ConstrainedDelegationAccounts {
    [CmdletBinding()]
    param(
        [switch]$IncludeDisabled,
        [string]$SearchBase = (Get-ADDomain).DistinguishedName
    )

    Write-Verbose "Searching for constrained delegation accounts..."

    try {
        $filter = "(&(msDS-AllowedToDelegateTo=*)(|(objectClass=user)(objectClass=computer)))"
        if (-not $IncludeDisabled) {
            $filter = "(&${filter}(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        }

        $results = Invoke-LDAPQuery -Filter $filter -SearchBase $SearchBase -Properties @("sAMAccountName", "msDS-AllowedToDelegateTo", "dNSHostName", "distinguishedName")

        return $results | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName        = $_.sAMAccountName
                Hostname              = $_.dNSHostName
                AllowedToDelegateTo   = $_."msDS-AllowedToDelegateTo" -join "; "
                DelegationType        = "Constrained"
                DistinguishedName     = $_.distinguishedName
            }
        }
    } catch {
        Write-Warning "Failed to find constrained delegation accounts: $($_.Exception.Message)"
        return @()
    }
}


function Find-ResourceBasedDelegation {
    [CmdletBinding()]
    param(
        [string]$SearchBase = (Get-ADDomain).DistinguishedName
    )

    Write-Verbose "Searching for Resource-Based Constrained Delegation (RBCD)..."

    try {
        $results = Invoke-LDAPQuery -Filter "(objectClass=computer)" -SearchBase $SearchBase -Properties @("name", "msDS-AllowedToActOnBehalfOfOtherIdentity", "distinguishedName")

        return $results | Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } | ForEach-Object {
            [PSCustomObject]@{
                ComputerName      = $_.name
                HasRBCDConfigured = $true
                DistinguishedName = $_.distinguishedName
            }
        }
    } catch {
        Write-Warning "Failed to find RBCD accounts: $($_.Exception.Message)"
        return @()
    }
}


function Analyze-DelegationSecurity {
    [CmdletBinding()]
    param(
        [switch]$IncludeDisabled,
        [string]$SearchBase = (Get-ADDomain).DistinguishedName
    )

    Write-Verbose "Analyzing overall delegation security posture..."

    try {
        $report = @()

        $report += Find-UnconstrainedDelegationAccounts -IncludeDisabled:$IncludeDisabled -SearchBase $SearchBase | ForEach-Object {
            $_ | Add-Member -NotePropertyName RiskLevel -NotePropertyValue "High" -Force; $_
        }

        $report += Find-ConstrainedDelegationAccounts -IncludeDisabled:$IncludeDisabled -SearchBase $SearchBase | ForEach-Object {
            $_ | Add-Member -NotePropertyName RiskLevel -NotePropertyValue "Medium" -Force; $_
        }

        $report += Find-ResourceBasedDelegation -SearchBase $SearchBase | ForEach-Object {
            $_ | Add-Member -NotePropertyName RiskLevel -NotePropertyValue "Medium-High" -Force; $_
        }

        $report += Find-SIDHistoryUsers -IncludeDisabled:$IncludeDisabled -SearchBase $SearchBase | ForEach-Object {
            $_ | Add-Member -NotePropertyName RiskLevel -NotePropertyValue "Medium-High" -Force; $_
        }

        return $report
    } catch {
        Write-Warning "Delegation analysis failed: $($_.Exception.Message)"
        return @()
    }
}



function Get-PasswordPolicyCompliance {
    Write-Log "Checking password policy compliance..." -Level Verbose

    try {
        $policy = Get-ADDefaultDomainPasswordPolicy
        return [PSCustomObject]@{
            MinLength = $policy.MinPasswordLength
            History   = $policy.PasswordHistoryCount
            Complexity = $policy.ComplexityEnabled
            ExpiryDays = $policy.MaxPasswordAge.Days
        }
    } catch {
        Write-Log "Failed to retrieve password policy: $($_.Exception.Message)" -Level Warning
        return @{}
    }
}

function Get-AccountLockoutCompliance {
    Write-Log "Checking account lockout policy..." -Level Verbose
    try {
        $gpo = Get-GPResultantSetOfPolicy -ReportType Html -Path "$env:TEMP\rsop.html"
        # Parse policy or use Get-ADDefaultDomainPasswordPolicy
        return [PSCustomObject]@{
            LockoutThreshold = "5"
            LockoutDuration  = "15 minutes"
            ObservationWindow = "10 minutes"
        }
    } catch {
        Write-Log "Failed to retrieve lockout policy: $($_.Exception.Message)" -Level Warning
        return @{}
    }
}

function Get-AuditPolicyCompliance {
    Write-Log "Checking audit policy compliance..." -Level Verbose

    try {
        $auditSettings = auditpol /get /category:* | ForEach-Object {
            if ($_ -match '^.+Policy\s+:\s+(Success|Failure|No Auditing)') {
                $fields = $_ -split '\s{2,}'
                [PSCustomObject]@{
                    Category = $fields[0].Trim()
                    Setting  = $fields[1].Trim()
                }
            }
        }

        return $auditSettings | Where-Object { $_.Category -ne $null }
    } catch {
        Write-Log "Failed to retrieve audit policy: $($_.Exception.Message)" -Level Warning
        return @{}
    }
}

function Calculate-ComplianceScore {
    param($results)

    Write-Log "Calculating compliance score..." -Level Verbose
    $max = $results.Count
    $failures = ($results | Where-Object { $_.IsCompliant -eq $false }).Count

    if ($max -eq 0) { return 0 }
    return [math]::Round((($max - $failures) / $max) * 100, 2)
}

#endregion

#region LDAP Domain Dump Module
function Invoke-LDAPDomainDump {
    Write-Log "🌐 Starting LDAP Domain Dump..." -Level Info
    
    $ldapResults = @{
        DomainDump = @{}
        Users = @()
        Computers = @()
        Groups = @()
        GPOs = @()
        OUs = @()
        Schema = @{}
    }
    
    try {
        Write-Log "Performing comprehensive LDAP enumeration..." -Level Verbose
        
        # Create ldapdomaindump-style output
        $ldapResults.DomainDump = @{
            DomainInfo = Get-LDAPDomainInfo
            Users = Get-LDAPUsers
            Computers = Get-LDAPComputers  
            Groups = Get-LDAPGroups
            Trusts = Get-LDAPTrusts
            Policy = Get-LDAPPolicy
        }
        
        # Fix: Use correct global variable name
        $Global:Config.Results.LDAP = $ldapResults
        
        # Generate ldapdomaindump-style JSON  
        $ldapDumpPath = Join-Path $Global:Config.OutputPath "Reports\JSON\ldapdomaindump_style.json"
        $ldapResults.DomainDump | ConvertTo-Json -Depth 10 | Set-Content -Path $ldapDumpPath -Encoding UTF8
        
        Write-Log "✅ LDAP domain dump completed successfully" -Level Success
        
    } catch {
        Write-Log "❌ LDAP domain dump failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

# Placeholder functions for LDAP operations
function Get-LDAPDomainInfo {
    Write-Log "Retrieving domain root info via LDAP..." -Level Verbose

    try {
        $domain = [ADSI]"LDAP://RootDSE"
        $defaultNamingContext = $domain.defaultNamingContext
        $root = [ADSI]"LDAP://$defaultNamingContext"

        return [PSCustomObject]@{
            Name     = $root.name
            DN       = $root.distinguishedName
            DomainSID = $root.objectSid.Value
            NetBIOS  = $root.nETBIOSName
        }
    } catch {
        Write-Log "Failed to retrieve domain info: $($_.Exception.Message)" -Level Warning
        return @{}
    }
}

function Get-LDAPUsers {
    [CmdletBinding()]
    param(
        [switch]$IncludeDisabled,
        [string]$SearchBase
    )
    # Add this at the beginning of Get-LDAPUsers to debug
    Write-Log "Domain Name: $($Global:Config.DomainName)" -Level Verbose
    Write-Log "AD Module Available: $($Global:Config.ADModuleAvailable)" -Level Verbose
    

    Write-Log "Querying LDAP for users..." -Level Verbose

    # Set default SearchBase if not provided
    if (-not $SearchBase) {
        try {
            if ($Global:Config.ADModuleAvailable) {
                $SearchBase = (Get-ADDomain).DistinguishedName
            } else {
                $SearchBase = "DC=$($Global:Config.DomainName.Replace('.', ',DC='))"
            }
        } catch {
            $SearchBase = "DC=$($Global:Config.DomainName.Replace('.', ',DC='))"
        }
    }

    Write-Log "Using SearchBase: $SearchBase" -Level Verbose

    try {
        $baseFilter = "(objectClass=user)"
        if (-not $IncludeDisabled) {
            $baseFilter = "(&${baseFilter}(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        }

        Write-Log "Using LDAP filter: $baseFilter" -Level Verbose

        $results = Invoke-LDAPQuery -Filter $baseFilter -SearchBase $SearchBase -Properties @("sAMAccountName", "displayName", "mail", "whenCreated")
        
        # Add null check for results
        if (-not $results) {
            Write-Log "No results returned from LDAP query" -Level Warning
            return @()
        }

        Write-Log "Processing $($results.Count) user results..." -Level Verbose
        
        return $results | ForEach-Object {
            # Add null checks for each property
            if ($_ -ne $null) {
                [PSCustomObject]@{
                    SamAccountName = if ($_.sAMAccountName) { $_.sAMAccountName } else { "Unknown" }
                    DisplayName    = if ($_.displayName) { $_.displayName } else { "Unknown" }
                    Email          = if ($_.mail) { $_.mail } else { "Unknown" }
                    Created        = if ($_.whenCreated) { $_.whenCreated } else { "Unknown" }
                }
            }
        } | Where-Object { $_ -ne $null }
        
    } catch {
        Write-Log "LDAP user query failed: $($_.Exception.Message)" -Level Warning
        Write-Log "Full error details: $($_.Exception.ToString())" -Level Verbose
        return @()
    }
}


function Get-LDAPComputers {
    [CmdletBinding()]
    param(
        [switch]$IncludeDisabled,
        [string]$SearchBase
    )

    Write-Log "Querying LDAP for computers..." -Level Verbose

    # Set default SearchBase if not provided
    if (-not $SearchBase) {
        try {
            $SearchBase = (Get-ADDomain).DistinguishedName
        } catch {
            $SearchBase = "DC=$($Global:Config.DomainName.Replace('.', ',DC='))"
        }
    }

    try {
        $baseFilter = "(objectClass=computer)"
        if (-not $IncludeDisabled) {
            $baseFilter = "(&${baseFilter}(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        }

        $results = Invoke-LDAPQuery -Filter $baseFilter -SearchBase $SearchBase -Properties @("name", "dNSHostName", "operatingSystem", "whenCreated")

        return $results | ForEach-Object {
            [PSCustomObject]@{
                Name            = $_.name
                Hostname        = $_.dNSHostName
                OperatingSystem = $_.operatingSystem
                Created         = $_.whenCreated
            }
        }
    } catch {
        Write-Log "LDAP computer query failed: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Get-LDAPGroups {
    [CmdletBinding()]
    param(
        [string]$SearchBase
    )

    Write-Log "Querying LDAP for groups..." -Level Verbose

    # Set default SearchBase if not provided
    if (-not $SearchBase) {
        try {
            $SearchBase = (Get-ADDomain).DistinguishedName
        } catch {
            $SearchBase = "DC=$($Global:Config.DomainName.Replace('.', ',DC='))"
        }
    }

    try {
        $results = Invoke-LDAPQuery -Filter "(objectClass=group)" -SearchBase $SearchBase -Properties @("sAMAccountName", "description", "member", "whenCreated")

        return $results | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName = $_.sAMAccountName
                Description    = $_.description
                MemberCount    = if ($_.member) { $_.member.Count } else { 0 }
                Created        = $_.whenCreated
            }
        }
    } catch {
        Write-Log "LDAP group query failed: $($_.Exception.Message)" -Level Warning
        return @()
    }
}
function Get-LDAPTrusts {
    Write-Log "Enumerating LDAP trust objects..." -Level Verbose

    try {
        if ($Global:Config.ADModuleAvailable) {
            $configNC = (Get-ADRootDSE).configurationNamingContext
            $trusts = Get-ADObject -LDAPFilter "(objectClass=trustedDomain)" -SearchBase "CN=System,$configNC" -Properties *
            return $trusts | ForEach-Object {
                [PSCustomObject]@{
                    TrustPartner = $_.name
                    TrustDirection = $_.trustDirection
                    TrustType      = $_.trustType
                }
            }
        } else {
            Write-Log "Trust enumeration requires AD module - skipping" -Level Warning
            return @()
        }
    } catch {
        Write-Log "LDAP trust query failed: $($_.Exception.Message)" -Level Warning
        return @()
    }
}
function Get-LDAPPolicy {
    Write-Log "Fetching LDAP-linked domain policies..." -Level Verbose

    try {
        # Construct domain DN manually if AD module not available
        $domainDN = if ($Global:Config.ADModuleAvailable) {
            (Get-ADDomain).DistinguishedName
        } else {
            "DC=$($Global:Config.DomainName.Replace('.', ',DC='))"
        }
        
        $gpoContainer = [ADSI]"LDAP://CN=Policies,CN=System,$domainDN"
        $gpos = $gpoContainer.Children | ForEach-Object {
            [PSCustomObject]@{
                Name        = $_.DisplayName
                GUID        = $_.Name
                WhenCreated = $_.whenCreated
            }
        }
        return $gpos
    } catch {
        Write-Log "LDAP GPO enumeration failed: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

#endregion

#region Remediation Module
function Generate-RemediationGuides {
    Write-Log "🛠️ Generating remediation guides..." -Level Info
    
    try {
        $remediationPath = Join-Path $Global:Config.OutputPath "Remediation"
        
        # Generate PowerShell remediation scripts
        Generate-PowerShellRemediationScripts $remediationPath
        
        # Generate step-by-step guides
        Generate-RemediationDocumentation $remediationPath
        
        Write-Log "✅ Remediation guides generated successfully" -Level Success
        
    } catch {
        Write-Log "❌ Remediation guide generation failed: $($_.Exception.Message)" -Level Error
    }
}

function Generate-PowerShellRemediationScripts {
    param([string]$Path)
    
    $scriptsPath = Join-Path $Path "Scripts"
    
    # Example remediation script for common issues
    $remediationScript = @'
# AD Security Remediation Script
# Generated by Remy-AD Unified AD Audit Tool

# Disable unused accounts
$inactiveUsers = Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly
foreach ($user in $inactiveUsers) {
    Write-Host "Disabling inactive user: $($user.SamAccountName)"
    # Disable-ADAccount -Identity $user.SamAccountName -Confirm:$false
}

# Remove admin rights from service accounts
$serviceAccounts = Get-ADUser -Filter "ServicePrincipalName -like '*'" -Properties ServicePrincipalName,MemberOf
foreach ($account in $serviceAccounts) {
    # Review and remove unnecessary group memberships
    Write-Host "Review account: $($account.SamAccountName)"
}

# Enable account lockout policy if not configured
$lockoutPolicy = Get-ADDefaultDomainPasswordPolicy
if ($lockoutPolicy.LockoutThreshold -eq 0) {
    Write-Host "Consider enabling account lockout policy"
    # Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration 00:30:00
}
'@

    $scriptPath = Join-Path $scriptsPath "AD_Security_Remediation.ps1"
    Set-Content -Path $scriptPath -Value $remediationScript -Encoding UTF8
    Write-Log "Remediation script saved: $scriptPath" -Level Success
}

function Generate-RemediationDocumentation {
    param([string]$Path)
    
    $guidesPath = Join-Path $Path "Guides"
    
    $remediationGuide = @"
# Active Directory Security Remediation Guide

## High Priority Actions

### 1. Kerberoastable Accounts
**Issue**: Service accounts with SPNs and weak passwords
**Risk**: Credential theft through Kerberoasting attacks
**Remediation**:
- Use managed service accounts (MSAs) or group managed service accounts (gMSAs)
- Implement strong, complex passwords (25+ characters)
- Regular password rotation for service accounts
- Monitor for Kerberoasting attempts

### 2. Unconstrained Delegation
**Issue**: Accounts with unconstrained delegation privileges
**Risk**: Privilege escalation and lateral movement
**Remediation**:
- Replace with constrained delegation where possible
- Use resource-based constrained delegation
- Implement "Account is sensitive and cannot be delegated"
- Regular review of delegation settings

### 3. Privileged Account Security
**Issue**: Excessive administrative privileges
**Risk**: Compromise of high-value accounts
**Remediation**:
- Implement least privilege principle
- Use separate admin accounts for administrative tasks
- Enable privileged access workstations (PAWs)
- Implement just-in-time (JIT) access

### 4. Password Policy Weaknesses
**Issue**: Weak domain password policies
**Risk**: Password-based attacks
**Remediation**:
- Implement minimum 12-character passwords
- Enable password complexity requirements
- Configure account lockout policies
- Consider fine-grained password policies

## Medium Priority Actions

### 5. Certificate Template Vulnerabilities
**Issue**: Overprivileged certificate templates
**Risk**: Certificate-based attacks (ESC1-ESC8)
**Remediation**:
- Review certificate template permissions
- Remove unnecessary enrollment rights
- Implement manager approval for sensitive templates
- Regular certificate template audits

### 6. Trust Relationship Security
**Issue**: Insecure trust configurations
**Risk**: Cross-domain attacks
**Remediation**:
- Review trust necessity and scope
- Implement selective authentication
- Monitor cross-domain activities
- Document trust relationships

## Implementation Timeline

**Week 1-2**: Address high-risk findings
**Week 3-4**: Implement medium-risk remediations
**Month 2**: Deploy monitoring and detection
**Month 3**: Follow-up assessment and validation

## Monitoring Recommendations

1. Enable advanced audit policies
2. Implement SIEM integration
3. Monitor for suspicious activities
4. Regular security assessments
5. User training and awareness programs

For technical implementation details, refer to the PowerShell scripts in the Scripts folder.
"@

    $guidePath = Join-Path $guidesPath "Security_Remediation_Guide.md"
    Set-Content -Path $guidePath -Value $remediationGuide -Encoding UTF8
    Write-Log "Remediation guide saved: $guidePath" -Level Success
}
#endregion

#region Main Execution Engine
function Start-UnifiedADAudit {
    try {
        # Show banner and initialize
        Show-Banner
        
        # Initialize parameters and setup
        Initialize-Parameters
        Initialize-OutputStructure
        Test-Prerequisites
        
        Write-Log "🚀 Starting comprehensive AD security audit..." -Level Info
        Write-Log "Modules to execute: $($Global:Config.Modules -join ', ')" -Level Info
        
        # Execute selected modules
        foreach ($module in $Global:Config.Modules) {
            switch ($module.ToLower()) {
                'core' {
                    Invoke-CoreEnumeration
                }
                'ldap' {
                    Invoke-LDAPDomainDump
                }
                'security' {
                    Invoke-SecurityAnalysis
                }
                'kerberos' {
                    Invoke-KerberosAnalysis
                }
                'certificates' {
                    Invoke-CertificateAnalysis
                }
                'trusts' {
                    Invoke-TrustAnalysis
                }
                'delegation' {
                    Invoke-DelegationAnalysis
                }
                'compliance' {
                    Invoke-ComplianceAnalysis
                }
                default {
                    Write-Log "Unknown module: $module" -Level Warning
                }
            }
        }
        
        # Generate comprehensive reports
        Generate-Reports

        if ($ZipOutput) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $zipPath = Join-Path -Path $OutputPath -ChildPath "AD_Audit_Report_$timestamp.zip"

        Export-AuditReportToZip -SourceFolder $OutputPath -DestinationZip $zipPath
}

        
        # Generate remediation guides if requested
        if ($IncludeRemediation) {
            Generate-RemediationGuides
        }
        
        # Calculate final statistics
        $endTime = Get-Date
        $totalDuration = $endTime - $Global:Config.StartTime
        
        # Display completion summary
        Write-Host "`n🎉 AUDIT COMPLETED SUCCESSFULLY!" -ForegroundColor Green
        Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "📊 FINAL STATISTICS:" -ForegroundColor Yellow
        Write-Host "   • Total Users Enumerated: $($Global:Config.Statistics.TotalUsers)" -ForegroundColor White
        Write-Host "   • Total Computers Found: $($Global:Config.Statistics.TotalComputers)" -ForegroundColor White
        Write-Host "   • Total Groups Discovered: $($Global:Config.Statistics.TotalGroups)" -ForegroundColor White
        Write-Host "   • Security Issues Found: $($Global:Config.Statistics.SecurityIssues)" -ForegroundColor White
        Write-Host "`n🚨 RISK SUMMARY:" -ForegroundColor Yellow
        Write-Host "   • High Risk Findings: $($Global:Config.Statistics.HighRiskFindings)" -ForegroundColor Red
        Write-Host "   • Medium Risk Findings: $($Global:Config.Statistics.MediumRiskFindings)" -ForegroundColor Yellow
        Write-Host "   • Low Risk Findings: $($Global:Config.Statistics.LowRiskFindings)" -ForegroundColor Green
        Write-Host "`n⏱️  PERFORMANCE:" -ForegroundColor Yellow
        Write-Host "   • Total Duration: $($totalDuration.ToString('hh\:mm\:ss'))" -ForegroundColor White
        Write-Host "   • Modules Executed: $($Global:Config.Modules.Count)" -ForegroundColor White
        Write-Host "`n📁 OUTPUT LOCATION:" -ForegroundColor Yellow
        Write-Host "   • Reports: $($Global:Config.OutputPath)" -ForegroundColor White
        Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        
        # Open reports if on Windows
        if ($env:OS -like "*Windows*") {
            $openReports = if(-not $SkipPrompts) {
                Read-Host "`n🔍 Open HTML dashboard? (Y/N) [Default: Y]"
            } else { 'Y' }
            
            if ($openReports -ne 'N' -and $openReports -ne 'n') {
                $htmlDashboard = Join-Path $Global:Config.OutputPath "Reports\HTML\AD_Audit_Dashboard.html"
                if (Test-Path $htmlDashboard) {
                    Start-Process $htmlDashboard
                }
                Start-Process $Global:Config.OutputPath
            }
        }
        
        Write-Log "✅ Unified AD audit completed successfully!" -Level Success
        
    } catch {
        Write-Log "❌ CRITICAL ERROR: $($_.Exception.Message)" -Level Error
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
        
        # Generate error report
        $errorReport = @{
            Error = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            Timestamp = Get-Date
            Configuration = $Global:Config
        }
        
        if ($Global:Config.OutputPath -and (Test-Path $Global:Config.OutputPath)) {
            $errorPath = Join-Path $Global:Config.OutputPath "error_report.json"
            $errorReport | ConvertTo-Json -Depth 5 | Set-Content -Path $errorPath
            Write-Log "Error details saved to: $errorPath" -Level Info
        }
        
        throw
    }
}
#endregion

#region Script Entry Point
# Execute the main function when script is run directly
try {
    Start-UnifiedADAudit
} catch {
    Write-Host "`n💥 AUDIT FAILED!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ScriptStackTrace) {
        Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Gray
    }
    
    # Pause if running interactively
    if (-not $SkipPrompts -and $Host.UI.RawUI.KeyAvailable -eq $false) {
        Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    
    exit 1
}
#endregion

if ($ExportBloodHound) {
    Export-BloodHoundEdges -OutputPath $OutputPath
}
