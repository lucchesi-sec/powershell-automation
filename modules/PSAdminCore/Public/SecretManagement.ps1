#Requires -Module Microsoft.PowerShell.SecretManagement
<#
.SYNOPSIS
    Secret management functions using Microsoft.PowerShell.SecretManagement for cross-platform support.
.DESCRIPTION
    Provides secure credential and secret management that works across Windows, Linux, and macOS.
#>

function Test-SecretManagementPrerequisites {
    <#
    .SYNOPSIS
        Verifies that SecretManagement module and vault are properly configured.
    .DESCRIPTION
        Checks for SecretManagement module installation and vault registration.
        Provides clear error messages with installation instructions if prerequisites are missing.
    .EXAMPLE
        Test-SecretManagementPrerequisites
        Verifies all prerequisites are met for secret management.
    #>
    [CmdletBinding()]
    param()

    try {
        # Check if SecretManagement module is available
        if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement -ErrorAction SilentlyContinue)) {
            throw @"
PSAdminCore requires the 'Microsoft.PowerShell.SecretManagement' module.
Please install it from the PowerShell Gallery:
    Install-Module -Name Microsoft.PowerShell.SecretManagement -Repository PSGallery -Force
    Install-Module -Name Microsoft.PowerShell.SecretStore -Repository PSGallery -Force
"@
        }

        # Import the module if not already loaded
        if (-not (Get-Module -Name Microsoft.PowerShell.SecretManagement)) {
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
        }

        # Check if at least one vault is registered
        $vaults = Get-SecretVault -ErrorAction SilentlyContinue
        if (-not $vaults) {
            Write-Warning @"
No secret vault has been configured. Setting up default SecretStore vault...
To set up manually, run:
    Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
"@
            
            # Try to auto-configure SecretStore if available
            if (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretStore -ErrorAction SilentlyContinue) {
                Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault -ErrorAction Stop
                Write-Information "Successfully registered SecretStore as default vault" -InformationAction Continue
            } else {
                throw "Microsoft.PowerShell.SecretStore module not found. Please install it first."
            }
        }

        return $true
    }
    catch {
        Write-Error "Secret management prerequisites check failed: $_"
        throw
    }
}

function Get-PSAdminCredential {
    <#
    .SYNOPSIS
        Retrieves credentials from the SecretManagement vault.
    .DESCRIPTION
        Gets stored credentials using the cross-platform SecretManagement module.
        Creates new credentials if they don't exist and Force is specified.
    .PARAMETER Target
        The name/identifier for the credential.
    .PARAMETER Username
        Username for new credential creation (with Force).
    .PARAMETER Force
        Creates new credential if it doesn't exist.
    .EXAMPLE
        Get-PSAdminCredential -Target "ADAdmin"
        Retrieves the ADAdmin credential from the vault.
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

    # Ensure prerequisites are met
    Test-SecretManagementPrerequisites

    try {
        # Try to get existing credential
        $credential = Get-Secret -Name $Target -AsPlainText:$false -ErrorAction SilentlyContinue
        
        if ($credential -and $credential -is [PSCredential]) {
            Write-Verbose "Retrieved credential for target: $Target"
            return $credential
        }
        
        if ($Force) {
            # Create new credential
            if (-not $Username) {
                $Username = Read-Host "Enter username for $Target"
            }
            
            $password = Read-Host "Enter password for $Target" -AsSecureString
            $credential = New-Object System.Management.Automation.PSCredential($Username, $password)
            
            # Store in vault
            Set-Secret -Name $Target -Secret $credential -ErrorAction Stop
            Write-Information "Credential stored successfully for: $Target" -InformationAction Continue
            
            return $credential
        }
        else {
            throw "Credential not found for target: $Target. Use -Force to create new credential."
        }
    }
    catch {
        Write-Error "Failed to get credential: $_"
        throw
    }
}

function Get-PSAdminCoreAesKey {
    <#
    .SYNOPSIS
        Gets or creates the AES encryption key for configuration protection.
    .DESCRIPTION
        Implements a get-or-create pattern for the AES key used in configuration encryption.
        The key is stored securely in the SecretManagement vault.
    .PARAMETER KeyName
        The name of the AES key in the vault (default: PSAdminCore-AES-FileEncryptionKey).
    .EXAMPLE
        $key = Get-PSAdminCoreAesKey
        Gets the AES encryption key, creating it if necessary.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$KeyName = 'PSAdminCore-AES-FileEncryptionKey'
    )

    # Ensure prerequisites are met
    Test-SecretManagementPrerequisites

    try {
        # Attempt to retrieve existing key
        $existingKey = Get-Secret -Name $KeyName -AsPlainText:$false -ErrorAction SilentlyContinue
        
        if ($existingKey) {
            Write-Verbose "Retrieved existing AES key: $KeyName"
            
            # Convert SecureString back to byte array
            $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($existingKey)
            try {
                $keyString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
                # Convert from base64 string back to bytes
                return [Convert]::FromBase64String($keyString)
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
            }
        }
        
        # Key doesn't exist, create new one
        Write-Warning "No existing AES key found with name '$KeyName'. Generating new key..."
        
        $aesKeyBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($aesKeyBytes)
        $rng.Dispose()
        
        # Convert to base64 for storage as SecureString
        $keyString = [Convert]::ToBase64String($aesKeyBytes)
        $secureKey = ConvertTo-SecureString -String $keyString -AsPlainText -Force
        
        # Store in vault
        Set-Secret -Name $KeyName -Secret $secureKey -ErrorAction Stop
        Write-Information "Generated and stored new AES key: $KeyName" -InformationAction Continue
        
        return $aesKeyBytes
    }
    catch {
        Write-Error "Failed to retrieve or create AES key '$KeyName': $_"
        throw
    }
}

function Protect-PSAdminConfiguration {
    <#
    .SYNOPSIS
        Encrypts configuration data using AES encryption.
    .DESCRIPTION
        Protects sensitive configuration data using AES encryption with a key stored in SecretManagement.
    .PARAMETER Data
        The configuration data to encrypt (hashtable or custom object).
    .PARAMETER OutputPath
        Path where the encrypted configuration will be saved.
    .EXAMPLE
        Protect-PSAdminConfiguration -Data @{Server="sql01"} -OutputPath "C:\config\encrypted.json"
        Encrypts and saves the configuration data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Data,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        # Get or create AES key
        $aesKey = Get-PSAdminCoreAesKey
        
        # Convert data to JSON
        $jsonData = $Data | ConvertTo-Json -Depth 10 -Compress
        $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonData)
        
        # Create AES provider
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $aesKey
        $aes.GenerateIV()
        
        # Encrypt data
        $encryptor = $aes.CreateEncryptor()
        $encryptedBytes = $encryptor.TransformFinalBlock($dataBytes, 0, $dataBytes.Length)
        
        # Combine IV and encrypted data
        $combinedData = $aes.IV + $encryptedBytes
        
        # Save to file
        $encryptedContent = @{
            Version = "1.0"
            Algorithm = "AES"
            Data = [Convert]::ToBase64String($combinedData)
            Timestamp = (Get-Date -Format "o")
        }
        
        $encryptedContent | ConvertTo-Json | Set-Content -Path $OutputPath -Encoding UTF8 -ErrorAction Stop
        
        Write-Information "Configuration encrypted and saved to: $OutputPath" -InformationAction Continue
        
        # Clean up
        $encryptor.Dispose()
        $aes.Dispose()
    }
    catch {
        Write-Error "Failed to encrypt configuration: $_"
        throw
    }
}

function Unprotect-PSAdminConfiguration {
    <#
    .SYNOPSIS
        Decrypts configuration data encrypted with Protect-PSAdminConfiguration.
    .DESCRIPTION
        Decrypts configuration files using the AES key from SecretManagement vault.
    .PARAMETER Path
        Path to the encrypted configuration file.
    .EXAMPLE
        $config = Unprotect-PSAdminConfiguration -Path "C:\config\encrypted.json"
        Decrypts and returns the configuration data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        if (-not (Test-Path -Path $Path)) {
            throw "Configuration file not found: $Path"
        }
        
        # Read encrypted file
        $encryptedContent = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        
        if ($encryptedContent.Algorithm -ne "AES") {
            throw "Unsupported encryption algorithm: $($encryptedContent.Algorithm)"
        }
        
        # Get AES key
        $aesKey = Get-PSAdminCoreAesKey
        
        # Convert from base64
        $combinedData = [Convert]::FromBase64String($encryptedContent.Data)
        
        # Extract IV (first 16 bytes) and encrypted data
        $iv = $combinedData[0..15]
        $encryptedBytes = $combinedData[16..($combinedData.Length - 1)]
        
        # Create AES provider
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $aesKey
        $aes.IV = $iv
        
        # Decrypt data
        $decryptor = $aes.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
        
        # Convert back to object
        $jsonData = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        $data = $jsonData | ConvertFrom-Json
        
        Write-Verbose "Configuration decrypted successfully"
        
        # Clean up
        $decryptor.Dispose()
        $aes.Dispose()
        
        return $data
    }
    catch {
        Write-Error "Failed to decrypt configuration: $_"
        throw
    }
}

function Test-PSAdminSecurityCompliance {
    <#
    .SYNOPSIS
        Validates security compliance of the PSAdmin environment.
    .DESCRIPTION
        Checks various security aspects including vault configuration, key management, and encryption status.
    .EXAMPLE
        Test-PSAdminSecurityCompliance
        Returns a compliance report with any issues found.
    #>
    [CmdletBinding()]
    param()

    $complianceResults = @{
        Compliant = $true
        Issues = @()
        Checks = @()
    }

    # Check SecretManagement prerequisites
    try {
        Test-SecretManagementPrerequisites
        $complianceResults.Checks += "✓ SecretManagement module installed and configured"
    }
    catch {
        $complianceResults.Compliant = $false
        $complianceResults.Issues += "✗ SecretManagement not properly configured: $_"
    }

    # Check for default vault
    try {
        $defaultVault = Get-SecretVault | Where-Object { $_.IsDefault }
        if ($defaultVault) {
            $complianceResults.Checks += "✓ Default vault configured: $($defaultVault.Name)"
        } else {
            $complianceResults.Issues += "⚠ No default vault configured"
        }
    }
    catch {
        $complianceResults.Issues += "✗ Failed to check vault configuration: $_"
    }

    # Check AES key exists
    try {
        $keyName = 'PSAdminCore-AES-FileEncryptionKey'
        $key = Get-Secret -Name $keyName -ErrorAction SilentlyContinue
        if ($key) {
            $complianceResults.Checks += "✓ AES encryption key is configured"
        } else {
            $complianceResults.Checks += "⚠ AES encryption key not found (will be created on first use)"
        }
    }
    catch {
        $complianceResults.Issues += "⚠ Could not verify AES key status: $_"
    }

    # Check PowerShell version for security features
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $complianceResults.Checks += "✓ Running PowerShell 7+ with latest security features"
    } elseif ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -ge 1) {
        $complianceResults.Checks += "⚠ Running Windows PowerShell 5.1 - consider upgrading to PowerShell 7+"
    } else {
        $complianceResults.Compliant = $false
        $complianceResults.Issues += "✗ PowerShell version too old for secure operations"
    }

    # Generate report
    $report = [PSCustomObject]@{
        Timestamp = Get-Date -Format "o"
        Compliant = $complianceResults.Compliant
        ChecksPassed = $complianceResults.Checks
        Issues = $complianceResults.Issues
        Recommendation = if ($complianceResults.Compliant) { 
            "System meets security compliance requirements" 
        } else { 
            "Address the identified issues to ensure security compliance" 
        }
    }

    return $report
}

# Export functions
Export-ModuleMember -Function @(
    'Test-SecretManagementPrerequisites',
    'Get-PSAdminCredential',
    'Get-PSAdminCoreAesKey',
    'Protect-PSAdminConfiguration',
    'Unprotect-PSAdminConfiguration',
    'Test-PSAdminSecurityCompliance'
)