# Security and Credential Management Functions

function Get-SecureCredential {
    <#
    .SYNOPSIS
        Retrieves stored credentials from Windows Credential Manager or prompts for new ones.
    
    .DESCRIPTION
        This function provides secure credential management using Windows Credential Manager
        for storage and retrieval. Falls back to prompting if credentials are not found.
    
    .PARAMETER Target
        The target name for the credential in Credential Manager
    
    .PARAMETER Username
        Optional username to use if prompting for credentials
    
    .PARAMETER Force
        Force prompting for new credentials even if stored ones exist
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,
        
        [Parameter()]
        [string]$Username,
        
        [Parameter()]
        [switch]$Force
    )
    
    try {
        # Check if running on Windows with CredentialManager module available
        if ($PSVersionTable.Platform -eq 'Win32NT' -or -not $PSVersionTable.Platform) {
            # Try to load CredentialManager module
            if (Get-Module -ListAvailable -Name CredentialManager) {
                Import-Module CredentialManager -ErrorAction Stop
                
                if (-not $Force) {
                    # Try to retrieve stored credential
                    $storedCred = Get-StoredCredential -Target $Target -ErrorAction SilentlyContinue
                    if ($storedCred) {
                        Write-AdminLog "Retrieved stored credential for target: $Target" -Level INFO
                        return $storedCred
                    }
                }
            }
        }
        
        # Prompt for credentials
        $promptParams = @{
            Message = "Enter credentials for $Target"
        }
        
        if ($Username) {
            $promptParams['UserName'] = $Username
        }
        
        $credential = Get-Credential @promptParams
        
        if ($credential) {
            # Try to store the credential if CredentialManager is available
            if (Get-Command -Name New-StoredCredential -ErrorAction SilentlyContinue) {
                try {
                    New-StoredCredential -Target $Target -Credentials $credential -Persist LocalMachine | Out-Null
                    Write-AdminLog "Stored credential for target: $Target" -Level INFO
                }
                catch {
                    Write-AdminLog "Could not store credential: $_" -Level WARNING
                }
            }
            
            return $credential
        }
        else {
            throw "No credentials provided"
        }
    }
    catch {
        Write-AdminLog "Error managing credentials for $Target`: $_" -Level ERROR
        throw
    }
}

function Test-SecureString {
    <#
    .SYNOPSIS
        Tests if a string is a valid SecureString
    
    .PARAMETER InputString
        The string to test
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputString
    )
    
    return $InputString -is [System.Security.SecureString]
}

function ConvertTo-SecureText {
    <#
    .SYNOPSIS
        Converts a SecureString to an encrypted standard string
    
    .PARAMETER SecureString
        The SecureString to convert
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecureString
    )
    
    try {
        $encryptedString = ConvertFrom-SecureString -SecureString $SecureString
        return $encryptedString
    }
    catch {
        Write-AdminLog "Error converting SecureString: $_" -Level ERROR
        throw
    }
}

function ConvertFrom-SecureText {
    <#
    .SYNOPSIS
        Converts an encrypted standard string back to a SecureString
    
    .PARAMETER EncryptedString
        The encrypted string to convert
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$EncryptedString
    )
    
    try {
        $secureString = ConvertTo-SecureString -String $EncryptedString
        return $secureString
    }
    catch {
        Write-AdminLog "Error converting to SecureString: $_" -Level ERROR
        throw
    }
}

function Protect-Configuration {
    <#
    .SYNOPSIS
        Encrypts sensitive configuration data
    
    .PARAMETER ConfigData
        Hashtable of configuration data to encrypt
    
    .PARAMETER KeyPath
        Path to encryption key file (creates if doesn't exist)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ConfigData,
        
        [Parameter()]
        [string]$KeyPath = "$env:ProgramData\PSAutomation\encryption.key"
    )
    
    try {
        # Ensure key directory exists
        $keyDir = Split-Path -Path $KeyPath -Parent
        if (-not (Test-Path $keyDir)) {
            New-Item -ItemType Directory -Path $keyDir -Force | Out-Null
        }
        
        # Generate or load encryption key
        if (-not (Test-Path $KeyPath)) {
            # Generate new AES key
            $key = New-Object byte[] 32
            [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
            
            # Save key with restricted permissions
            $key | Set-Content -Path $KeyPath -Encoding Byte
            
            # Set restrictive permissions (Windows)
            if ($PSVersionTable.Platform -eq 'Win32NT' -or -not $PSVersionTable.Platform) {
                $acl = Get-Acl $KeyPath
                $acl.SetAccessRuleProtection($true, $false)
                $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "BUILTIN\Administrators", "FullControl", "Allow"
                )
                $acl.SetAccessRule($adminRule)
                Set-Acl -Path $KeyPath -AclObject $acl
            }
            
            Write-AdminLog "Generated new encryption key at: $KeyPath" -Level INFO
        }
        else {
            $key = Get-Content -Path $KeyPath -Encoding Byte
        }
        
        # Encrypt sensitive fields
        $protectedConfig = @{}
        $sensitiveFields = @('Password', 'ApiKey', 'Secret', 'Token', 'Credential')
        
        foreach ($item in $ConfigData.GetEnumerator()) {
            $isSensitive = $false
            foreach ($field in $sensitiveFields) {
                if ($item.Key -like "*$field*") {
                    $isSensitive = $true
                    break
                }
            }
            
            if ($isSensitive) {
                # Encrypt the value
                $secureString = ConvertTo-SecureString -String $item.Value -AsPlainText -Force
                $encryptedString = ConvertFrom-SecureString -SecureString $secureString -Key $key
                $protectedConfig[$item.Key] = @{
                    Type = 'Encrypted'
                    Value = $encryptedString
                }
                Write-AdminLog "Encrypted field: $($item.Key)" -Level DEBUG
            }
            else {
                $protectedConfig[$item.Key] = $item.Value
            }
        }
        
        return $protectedConfig
    }
    catch {
        Write-AdminLog "Error protecting configuration: $_" -Level ERROR
        throw
    }
}

function Unprotect-Configuration {
    <#
    .SYNOPSIS
        Decrypts sensitive configuration data
    
    .PARAMETER ProtectedConfig
        Protected configuration data to decrypt
    
    .PARAMETER KeyPath
        Path to encryption key file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ProtectedConfig,
        
        [Parameter()]
        [string]$KeyPath = "$env:ProgramData\PSAutomation\encryption.key"
    )
    
    try {
        if (-not (Test-Path $KeyPath)) {
            throw "Encryption key not found at: $KeyPath"
        }
        
        $key = Get-Content -Path $KeyPath -Encoding Byte
        
        # Decrypt sensitive fields
        $configData = @{}
        
        foreach ($item in $ProtectedConfig.GetEnumerator()) {
            if ($item.Value -is [hashtable] -and $item.Value.Type -eq 'Encrypted') {
                # Decrypt the value
                $secureString = ConvertTo-SecureString -String $item.Value.Value -Key $key
                $plainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
                )
                $configData[$item.Key] = $plainText
                Write-AdminLog "Decrypted field: $($item.Key)" -Level DEBUG
            }
            else {
                $configData[$item.Key] = $item.Value
            }
        }
        
        return $configData
    }
    catch {
        Write-AdminLog "Error unprotecting configuration: $_" -Level ERROR
        throw
    }
}

function Test-SecurityCompliance {
    <#
    .SYNOPSIS
        Checks if the current environment meets security requirements
    
    .DESCRIPTION
        Validates various security settings and configurations
    #>
    [CmdletBinding()]
    param()
    
    $complianceResults = @{
        Compliant = $true
        Issues = @()
        Warnings = @()
    }
    
    try {
        # Check PowerShell version
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            $complianceResults.Issues += "PowerShell version $($PSVersionTable.PSVersion) is below minimum required version 5.0"
            $complianceResults.Compliant = $false
        }
        
        # Check execution policy
        $executionPolicy = Get-ExecutionPolicy
        if ($executionPolicy -eq 'Unrestricted') {
            $complianceResults.Warnings += "Execution policy is set to Unrestricted, consider using RemoteSigned or more restrictive"
        }
        
        # Check if running as administrator (Windows)
        if ($PSVersionTable.Platform -eq 'Win32NT' -or -not $PSVersionTable.Platform) {
            $isAdmin = Test-AdminPrivileges
            if (-not $isAdmin) {
                $complianceResults.Warnings += "Not running with administrator privileges"
            }
        }
        
        # Check TLS version
        $tlsVersions = [System.Net.ServicePointManager]::SecurityProtocol
        if ($tlsVersions -notmatch 'Tls12|Tls13') {
            $complianceResults.Issues += "TLS 1.2 or higher is not enabled"
            $complianceResults.Compliant = $false
            
            # Try to enable TLS 1.2
            try {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                $complianceResults.Warnings += "TLS 1.2 has been enabled for this session"
            }
            catch {
                $complianceResults.Issues += "Could not enable TLS 1.2: $_"
            }
        }
        
        # Check module signing (if signature validation is enabled)
        $moduleInfo = Get-Module PSAdminCore
        if ($moduleInfo) {
            $signature = Get-AuthenticodeSignature -FilePath $moduleInfo.Path -ErrorAction SilentlyContinue
            if ($signature -and $signature.Status -ne 'Valid') {
                $complianceResults.Warnings += "PSAdminCore module is not digitally signed"
            }
        }
        
        # Check for sensitive data in environment variables
        $sensitiveEnvVars = @('PASSWORD', 'TOKEN', 'KEY', 'SECRET')
        foreach ($envVar in $sensitiveEnvVars) {
            $matches = Get-ChildItem env: | Where-Object { $_.Name -like "*$envVar*" }
            if ($matches) {
                $complianceResults.Warnings += "Potential sensitive data found in environment variables: $($matches.Name -join ', ')"
            }
        }
        
        return $complianceResults
    }
    catch {
        Write-AdminLog "Error checking security compliance: $_" -Level ERROR
        $complianceResults.Issues += "Error during compliance check: $_"
        $complianceResults.Compliant = $false
        return $complianceResults
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Get-SecureCredential',
    'Test-SecureString',
    'ConvertTo-SecureText',
    'ConvertFrom-SecureText',
    'Protect-Configuration',
    'Unprotect-Configuration',
    'Test-SecurityCompliance'
)