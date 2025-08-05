<#
.SYNOPSIS
    Tests backup integrity and validates backup files for successful recovery operations.
.DESCRIPTION
    This script performs comprehensive backup validation including file integrity checks,
    compression validation, encryption verification, and test restoration procedures.
    Supports automated scheduling and detailed reporting for backup verification workflows.
.PARAMETER BackupPath
    Path to backup files or backup repository to validate.
.PARAMETER ValidationMode
    Type of validation: Quick, Standard, or Full.
.PARAMETER TestRestorePath
    Temporary path for test restoration operations.
.PARAMETER ChecksumFile
    Path to checksum file for integrity verification.
.PARAMETER EncryptionKey
    Path to encryption key for encrypted backup validation.
.PARAMETER SampleSize
    Percentage of files to validate in Quick mode (default: 10).
.PARAMETER EmailAlerts
    If specified, sends email alerts for validation failures.
.PARAMETER GenerateReport
    If specified, generates detailed validation report.
.EXAMPLE
    .\Test-BackupIntegrity.ps1 -BackupPath "\\backup-server\backups" -ValidationMode "Standard"
.EXAMPLE
    .\Test-BackupIntegrity.ps1 -BackupPath "C:\Backups" -ValidationMode "Full" -TestRestorePath "C:\TestRestore"
.NOTES
    Author: System Administrator
    Requires: PSAdminCore module, backup file access permissions
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupPath,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Quick", "Standard", "Full")]
    [string]$ValidationMode = "Standard",
    
    [Parameter(Mandatory = $false)]
    [string]$TestRestorePath = "$env:TEMP\BackupValidation",
    
    [Parameter(Mandatory = $false)]
    [string]$ChecksumFile,
    
    [Parameter(Mandatory = $false)]
    [string]$EncryptionKey,
    
    [Parameter(Mandatory = $false)]
    [int]$SampleSize = 10,
    
    [Parameter(Mandatory = $false)]
    [switch]$EmailAlerts,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport
)

# Import required modules

if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
} else {
    # Fall back to installed module
    Import-Module PSAdminCore -Force -ErrorAction Stop
}

    Import-Module PSAdminCore -Force -ErrorAction Stop
}

Write-AdminLog -Message "Starting backup integrity validation (Mode: $ValidationMode)" -Level "Info"

# Function to calculate file hash
function Get-FileChecksum {
    param(
        [string]$FilePath,
        [string]$Algorithm = "SHA256"
    )
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm
        return $hash.Hash
    } catch {
        Write-AdminLog -Message "Failed to calculate checksum for $FilePath`: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

# Function to test compressed file integrity
function Test-CompressedFile {
    param([string]$ZipPath)
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
        
        $totalEntries = $zip.Entries.Count
        $corruptedEntries = 0
        
        foreach ($entry in $zip.Entries) {
            try {
                $stream = $entry.Open()
                $buffer = New-Object byte[] 1024
                while ($stream.Read($buffer, 0, $buffer.Length) -gt 0) {
                    # Reading through the stream to detect corruption
                }
                $stream.Close()
            } catch {
                $corruptedEntries++
                Write-AdminLog -Message "Corrupted entry found in $ZipPath`: $($entry.FullName)" -Level "Warning"
            }
        }
        
        $zip.Dispose()
        
        return @{
            IsValid = ($corruptedEntries -eq 0)
            TotalEntries = $totalEntries
            CorruptedEntries = $corruptedEntries
            CorruptionPercentage = if ($totalEntries -gt 0) { [math]::Round(($corruptedEntries / $totalEntries) * 100, 2) } else { 0 }
        }
    } catch {
        Write-AdminLog -Message "Failed to validate compressed file $ZipPath`: $($_.Exception.Message)" -Level "Error"
        return @{
            IsValid = $false
            TotalEntries = 0
            CorruptedEntries = 0
            CorruptionPercentage = 100
            Error = $_.Exception.Message
        }
    }
}

# Function to test encrypted file
function Test-EncryptedFile {
    param(
        [string]$FilePath,
        [string]$KeyPath
    )
    
    try {
        if (-not (Test-Path $KeyPath)) {
            return @{ IsValid = $false; Error = "Encryption key not found" }
        }
        
        # Simple decryption test (for demo - use proper encryption in production)
        $encryptedBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        
        return @{
            IsValid = $true
            DecryptedSize = $decryptedBytes.Length
            Error = $null
        }
    } catch {
        return @{
            IsValid = $false
            DecryptedSize = 0
            Error = $_.Exception.Message
        }
    }
}

# Function to perform test restoration
function Test-BackupRestoration {
    param(
        [string]$BackupFile,
        [string]$RestorePath,
        [string]$KeyPath = $null
    )
    
    try {
        # Create restore directory
        if (-not (Test-Path $RestorePath)) {
            New-Item -Path $RestorePath -ItemType Directory -Force | Out-Null
        }
        
        $isEncrypted = $BackupFile -like "*.encrypted" -or ($KeyPath -and (Test-Path $KeyPath))
        $isCompressed = $BackupFile -like "*.zip"
        
        if ($isEncrypted) {
            # Decrypt first
            $decryptResult = Test-EncryptedFile -FilePath $BackupFile -KeyPath $KeyPath
            if (-not $decryptResult.IsValid) {
                throw "Decryption failed: $($decryptResult.Error)"
            }
        }
        
        if ($isCompressed) {
            # Extract compressed backup
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($BackupFile, $RestorePath)
        } else {
            # Copy uncompressed backup
            Copy-Item $BackupFile $RestorePath -Recurse -Force
        }
        
        # Verify restored files
        $restoredFiles = Get-ChildItem $RestorePath -Recurse -File
        $totalSize = ($restoredFiles | Measure-Object Length -Sum).Sum
        
        return @{
            Success = $true
            RestoredFiles = $restoredFiles.Count
            TotalSizeMB = [math]::Round($totalSize / 1MB, 2)
            Error = $null
        }
    } catch {
        return @{
            Success = $false
            RestoredFiles = 0
            TotalSizeMB = 0
            Error = $_.Exception.Message
        }
    }
}

try {
    # Validate backup path exists
    if (-not (Test-Path $BackupPath)) {
        throw "Backup path not found: $BackupPath"
    }
    
    Write-AdminLog -Message "Scanning backup files in: $BackupPath" -Level "Info"
    
    # Get all backup files
    $backupFiles = Get-ChildItem $BackupPath -Recurse -File | Where-Object {
        $_.Extension -in @('.zip', '.bak', '.backup') -or 
        $_.Name -like "*backup*" -or 
        $_.Name -like "*.encrypted"
    }
    
    if ($backupFiles.Count -eq 0) {
        Write-AdminLog -Message "No backup files found in specified path" -Level "Warning"
    }
    
    Write-AdminLog -Message "Found $($backupFiles.Count) backup files to validate" -Level "Info"
    
    # Load existing checksums if available
    $existingChecksums = @{}
    if ($ChecksumFile -and (Test-Path $ChecksumFile)) {
        try {
            $checksumData = Get-Content $ChecksumFile | ConvertFrom-Json
            foreach ($item in $checksumData) {
                $existingChecksums[$item.FileName] = $item.Checksum
            }
            Write-AdminLog -Message "Loaded $($existingChecksums.Count) existing checksums" -Level "Info"
        } catch {
            Write-AdminLog -Message "Failed to load checksum file: $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    # Determine files to validate based on mode
    $filesToValidate = switch ($ValidationMode) {
        "Quick" {
            $sampleCount = [math]::Max(1, [math]::Ceiling($backupFiles.Count * ($SampleSize / 100)))
            $backupFiles | Get-Random -Count $sampleCount
        }
        "Standard" {
            $backupFiles | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
        }
        "Full" {
            $backupFiles
        }
    }
    
    Write-AdminLog -Message "Validating $($filesToValidate.Count) files in $ValidationMode mode" -Level "Info"
    
    $validationResults = @()
    $passedCount = 0
    $failedCount = 0
    $warningCount = 0
    
    foreach ($file in $filesToValidate) {
        $startTime = Get-Date
        
        try {
            Write-AdminLog -Message "Validating: $($file.Name)" -Level "Info"
            
            $result = [PSCustomObject]@{
                FileName = $file.Name
                FilePath = $file.FullName
                FileSizeMB = [math]::Round($file.Length / 1MB, 2)
                LastModified = $file.LastWriteTime
                ValidationMode = $ValidationMode
                StartTime = $startTime
                EndTime = $null
                Duration = $null
                Status = "Unknown"
                ChecksumMatch = $null
                CompressionValid = $null
                EncryptionValid = $null
                TestRestoreValid = $null
                Issues = @()
                Recommendations = @()
            }
            
            # File existence and size check
            if ($file.Length -eq 0) {
                $result.Issues += "File is empty"
                $result.Status = "Failed"
            }
            
            # Checksum validation
            if ($existingChecksums.ContainsKey($file.Name)) {
                $currentChecksum = Get-FileChecksum -FilePath $file.FullName
                if ($currentChecksum -eq $existingChecksums[$file.Name]) {
                    $result.ChecksumMatch = $true
                    Write-AdminLog -Message "Checksum validation passed for $($file.Name)" -Level "Success"
                } else {
                    $result.ChecksumMatch = $false
                    $result.Issues += "Checksum mismatch detected"
                    Write-AdminLog -Message "Checksum validation failed for $($file.Name)" -Level "Error"
                }
            } else {
                # Generate new checksum
                $newChecksum = Get-FileChecksum -FilePath $file.FullName
                if ($newChecksum) {
                    $result.ChecksumMatch = "Generated"
                    # Store for future reference
                    $existingChecksums[$file.Name] = $newChecksum
                }
            }
            
            # Compression validation
            if ($file.Extension -eq '.zip' -or $file.Name -like "*.zip") {
                $compressionTest = Test-CompressedFile -ZipPath $file.FullName
                $result.CompressionValid = $compressionTest.IsValid
                
                if (-not $compressionTest.IsValid) {
                    $result.Issues += "Compression validation failed: $($compressionTest.CorruptionPercentage)% corrupted"
                    Write-AdminLog -Message "Compression validation failed for $($file.Name)" -Level "Error"
                } else {
                    Write-AdminLog -Message "Compression validation passed for $($file.Name)" -Level "Success"
                }
            }
            
            # Encryption validation
            if ($file.Name -like "*.encrypted" -and $EncryptionKey) {
                $encryptionTest = Test-EncryptedFile -FilePath $file.FullName -KeyPath $EncryptionKey
                $result.EncryptionValid = $encryptionTest.IsValid
                
                if (-not $encryptionTest.IsValid) {
                    $result.Issues += "Encryption validation failed: $($encryptionTest.Error)"
                    Write-AdminLog -Message "Encryption validation failed for $($file.Name)" -Level "Error"
                } else {
                    Write-AdminLog -Message "Encryption validation passed for $($file.Name)" -Level "Success"
                }
            }
            
            # Test restoration (Full mode only)
            if ($ValidationMode -eq "Full") {
                $testRestorePath = Join-Path $TestRestorePath $file.BaseName
                $restoreTest = Test-BackupRestoration -BackupFile $file.FullName -RestorePath $testRestorePath -KeyPath $EncryptionKey
                $result.TestRestoreValid = $restoreTest.Success
                
                if ($restoreTest.Success) {
                    $result.Recommendations += "Test restoration successful: $($restoreTest.RestoredFiles) files, $($restoreTest.TotalSizeMB) MB"
                    Write-AdminLog -Message "Test restoration passed for $($file.Name)" -Level "Success"
                    
                    # Clean up test files
                    Remove-Item $testRestorePath -Recurse -Force -ErrorAction SilentlyContinue
                } else {
                    $result.Issues += "Test restoration failed: $($restoreTest.Error)"
                    Write-AdminLog -Message "Test restoration failed for $($file.Name)" -Level "Error"
                }
            }
            
            # Age recommendations
            $fileAge = (Get-Date) - $file.LastWriteTime
            if ($fileAge.TotalDays -gt 30) {
                $result.Recommendations += "Backup is $([math]::Round($fileAge.TotalDays, 0)) days old - consider retention policy review"
            }
            
            # Size recommendations
            if ($file.Length -gt 5GB) {
                $result.Recommendations += "Large backup file ($($result.FileSizeMB) MB) - consider splitting or compression optimization"
            }
            
            # Determine overall status
            if ($result.Issues.Count -eq 0) {
                $result.Status = "Passed"
                $passedCount++
            } elseif ($result.Issues | Where-Object { $_ -like "*failed*" -or $_ -like "*mismatch*" }) {
                $result.Status = "Failed"
                $failedCount++
            } else {
                $result.Status = "Warning"
                $warningCount++
            }
            
            $result.EndTime = Get-Date
            $result.Duration = $result.EndTime - $result.StartTime
            $validationResults += $result
            
            Write-AdminLog -Message "Validation completed for $($file.Name): $($result.Status)" -Level "Info"
            
        } catch {
            $result.EndTime = Get-Date
            $result.Duration = $result.EndTime - $result.StartTime
            $result.Status = "Error"
            $result.Issues += $_.Exception.Message
            $validationResults += $result
            $failedCount++
            
            Write-AdminLog -Message "Validation error for $($file.Name): $($_.Exception.Message)" -Level "Error"
        }
    }
    
    # Update checksum file if new checksums were generated
    if ($ChecksumFile -and $existingChecksums.Count -gt 0) {
        try {
            $checksumOutput = @()
            foreach ($key in $existingChecksums.Keys) {
                $checksumOutput += [PSCustomObject]@{
                    FileName = $key
                    Checksum = $existingChecksums[$key]
                    Generated = Get-Date
                }
            }
            $checksumOutput | ConvertTo-Json | Out-File -FilePath $ChecksumFile -Encoding UTF8
            Write-AdminLog -Message "Updated checksum file: $ChecksumFile" -Level "Success"
        } catch {
            Write-AdminLog -Message "Failed to update checksum file: $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    # Generate summary statistics
    $summary = @{
        TotalFiles = $backupFiles.Count
        ValidatedFiles = $validationResults.Count
        PassedFiles = $passedCount
        FailedFiles = $failedCount
        WarningFiles = $warningCount
        ValidationMode = $ValidationMode
        SuccessRate = if ($validationResults.Count -gt 0) { [math]::Round(($passedCount / $validationResults.Count) * 100, 2) } else { 0 }
        TotalBackupSizeMB = [math]::Round(($backupFiles | Measure-Object Length -Sum).Sum / 1MB, 2)
        AverageValidationTime = if ($validationResults.Count -gt 0) { 
            [math]::Round(($validationResults | Measure-Object { $_.Duration.TotalSeconds } -Average).Average, 2) 
        } else { 0 }
    }
    
    # Send email alerts for failures
    if ($EmailAlerts -and $failedCount -gt 0) {
        $subject = "Backup Validation Alert - $failedCount Failed"
        $failedFiles = $validationResults | Where-Object { $_.Status -eq "Failed" }
        
        $body = @"
Backup Validation Alert

Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Validation Mode: $ValidationMode
Backup Path: $BackupPath

Summary:
- Total Files: $($summary.TotalFiles)
- Validated: $($summary.ValidatedFiles)
- Passed: $passedCount
- Failed: $failedCount
- Warnings: $warningCount
- Success Rate: $($summary.SuccessRate)%

Failed Files:
$($failedFiles | ForEach-Object { "- $($_.FileName): $($_.Issues -join '; ')" } | Out-String)

Please investigate these backup integrity issues immediately.
"@
        
        try {
            Send-AdminNotification -Subject $subject -Body $body -Priority "High"
            Write-AdminLog -Message "Alert email sent for backup validation failures" -Level "Success"
        } catch {
            Write-AdminLog -Message "Failed to send email alert: $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    # Generate detailed report
    if ($GenerateReport) {
        $reportPath = Join-Path $BackupPath "BackupValidation-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        try {
            @{
                Summary = $summary
                ValidationResults = $validationResults
                GeneratedDate = Get-Date
                Parameters = @{
                    BackupPath = $BackupPath
                    ValidationMode = $ValidationMode
                    SampleSize = $SampleSize
                }
            } | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportPath -Encoding UTF8
            
            Write-AdminLog -Message "Detailed report saved: $reportPath" -Level "Success"
        } catch {
            Write-AdminLog -Message "Failed to generate report: $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    # Generate final report
    $report = New-AdminReport -ReportTitle "Backup Integrity Validation" -Data $validationResults -Description "Backup file integrity validation results" -Metadata $summary
    
    Write-Output $report
    
    # Summary
    Write-AdminLog -Message "Backup validation complete. Passed: $passedCount, Failed: $failedCount, Warnings: $warningCount (Success Rate: $($summary.SuccessRate)%)" -Level "Success"
    
} catch {
    Write-AdminLog -Message "Backup integrity validation failed: $($_.Exception.Message)" -Level "Error"
    throw
}
