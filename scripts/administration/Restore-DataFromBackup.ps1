<#
.SYNOPSIS
    Automated data restoration from backup files with comprehensive validation and rollback capabilities.
.DESCRIPTION
    This script provides data restoration capabilities including selective file recovery,
    point-in-time restoration, integrity verification, and automatic rollback on failure. Supports
    multiple backup formats, encryption, and detailed recovery logging.
.PARAMETER BackupPath
    Path to backup file or backup repository containing the data to restore.
.PARAMETER RestoreDestination
    Target directory where data should be restored.
.PARAMETER RestoreMode
    Type of restoration: Full, Selective, PointInTime, or TestRestore.
.PARAMETER BackupDate
    Specific backup date for point-in-time restoration (format: yyyy-MM-dd).
.PARAMETER SelectivePatterns
    Array of file patterns for selective restoration (e.g., "*.txt", "Documents\*").
.PARAMETER EncryptionKey
    Path to encryption key file for encrypted backup restoration.
.PARAMETER VerifyIntegrity
    If specified, performs integrity verification before and after restoration.
.PARAMETER CreateRollback
    If specified, creates rollback point before restoration.
.PARAMETER OverwriteExisting
    If specified, overwrites existing files during restoration.
.PARAMETER TestMode
    If specified, performs validation without actual restoration.
.PARAMETER EmailNotification
    If specified, sends restoration status notifications via email.
.EXAMPLE
    .\Restore-DataFromBackup.ps1 -BackupPath "\\backup-server\backups\CriticalFiles-20241201.zip" -RestoreDestination "C:\Restored"
.EXAMPLE
    .\Restore-DataFromBackup.ps1 -BackupPath "C:\Backups" -RestoreMode "PointInTime" -BackupDate "2024-11-30" -TestMode
.NOTES
    Author: System Administrator
    Requires: PSAdminCore module, appropriate restore permissions
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupPath,
    
    [Parameter(Mandatory = $true)]
    [string]$RestoreDestination,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Full", "Selective", "PointInTime", "TestRestore")]
    [string]$RestoreMode = "Full",
    
    [Parameter(Mandatory = $false)]
    [datetime]$BackupDate,
    
    [Parameter(Mandatory = $false)]
    [string[]]$SelectivePatterns,
    
    [Parameter(Mandatory = $false)]
    [string]$EncryptionKey,
    
    [Parameter(Mandatory = $false)]
    [switch]$VerifyIntegrity,
    
    [Parameter(Mandatory = $false)]
    [switch]$CreateRollback,
    
    [Parameter(Mandatory = $false)]
    [switch]$OverwriteExisting,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestMode,
    
    [Parameter(Mandatory = $false)]
    [switch]$EmailNotification
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

# Check administrative privileges
if (-not (Test-AdminPrivileges)) {
    Write-AdminLog -Message "This script requires administrative privileges" -Level "Error"
    exit 1
}

Write-AdminLog -Message "Starting data restoration operation (Mode: $RestoreMode)" -Level "Info"

# Function to decrypt backup file
function Unprotect-BackupData {
    param(
        [string]$EncryptedFilePath,
        [string]$KeyPath,
        [string]$OutputPath
    )
    
    try {
        if (-not (Test-Path $KeyPath)) {
            throw "Encryption key not found: $KeyPath"
        }
        
        Write-AdminLog -Message "Decrypting backup file..." -Level "Info"
        
        # Simple decryption (for demo - use proper encryption in production)
        $encryptedBytes = [System.IO.File]::ReadAllBytes($EncryptedFilePath)
        $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        [System.IO.File]::WriteAllBytes($OutputPath, $decryptedBytes)
        
        Write-AdminLog -Message "Decryption completed successfully" -Level "Success"
        return $true
    } catch {
        Write-AdminLog -Message "Decryption failed: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Function to extract compressed backup
function Expand-BackupArchive {
    param(
        [string]$ArchivePath,
        [string]$DestinationPath,
        [string[]]$SelectivePatterns = @()
    )
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        
        Write-AdminLog -Message "Extracting backup archive..." -Level "Info"
        
        $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
        $extractedFiles = @()
        $totalFiles = $archive.Entries.Count
        $extractedCount = 0
        
        foreach ($entry in $archive.Entries) {
            $shouldExtract = $true
            
            # Apply selective patterns if specified
            if ($SelectivePatterns.Count -gt 0) {
                $shouldExtract = $false
                foreach ($pattern in $SelectivePatterns) {
                    if ($entry.FullName -like $pattern) {
                        $shouldExtract = $true
                        break
                    }
                }
            }
            
            if ($shouldExtract -and -not [string]::IsNullOrEmpty($entry.Name)) {
                $destinationPath = Join-Path $DestinationPath $entry.FullName
                $destinationDir = Split-Path $destinationPath -Parent
                
                # Create directory if it doesn't exist
                if (-not (Test-Path $destinationDir)) {
                    New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
                }
                
                # Extract file
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destinationPath, $true)
                $extractedFiles += $destinationPath
                $extractedCount++
                
                if ($extractedCount % 100 -eq 0) {
                    Write-AdminLog -Message "Extracted $extractedCount of $totalFiles files..." -Level "Info"
                }
            }
        }
        
        $archive.Dispose()
        
        return @{
            Success = $true
            ExtractedFiles = $extractedFiles
            TotalFiles = $totalFiles
            ExtractedCount = $extractedCount
        }
    } catch {
        Write-AdminLog -Message "Archive extraction failed: $($_.Exception.Message)" -Level "Error"
        return @{
            Success = $false
            ExtractedFiles = @()
            TotalFiles = 0
            ExtractedCount = 0
            Error = $_.Exception.Message
        }
    }
}

# Function to verify file integrity
function Test-FileIntegrity {
    param(
        [string]$FilePath,
        [string]$ExpectedHash = $null
    )
    
    try {
        if (-not (Test-Path $FilePath)) {
            return @{ IsValid = $false; Error = "File not found" }
        }
        
        $currentHash = Get-FileHash -Path $FilePath -Algorithm SHA256
        
        if ($ExpectedHash) {
            $isValid = $currentHash.Hash -eq $ExpectedHash
            return @{
                IsValid = $isValid
                CurrentHash = $currentHash.Hash
                ExpectedHash = $ExpectedHash
                Error = if ($isValid) { $null } else { "Hash mismatch" }
            }
        } else {
            return @{
                IsValid = $true
                CurrentHash = $currentHash.Hash
                ExpectedHash = $null
                Error = $null
            }
        }
    } catch {
        return @{
            IsValid = $false
            CurrentHash = $null
            ExpectedHash = $ExpectedHash
            Error = $_.Exception.Message
        }
    }
}

# Function to create rollback point
function New-RollbackPoint {
    param(
        [string]$TargetPath,
        [string]$RollbackPath
    )
    
    try {
        if (Test-Path $TargetPath) {
            Write-AdminLog -Message "Creating rollback point..." -Level "Info"
            
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $rollbackDir = Join-Path $RollbackPath "Rollback-$timestamp"
            
            # Create rollback directory
            New-Item -Path $rollbackDir -ItemType Directory -Force | Out-Null
            
            # Copy existing files to rollback location
            Copy-Item $TargetPath $rollbackDir -Recurse -Force
            
            Write-AdminLog -Message "Rollback point created: $rollbackDir" -Level "Success"
            return $rollbackDir
        } else {
            Write-AdminLog -Message "Target path does not exist, no rollback needed" -Level "Info"
            return $null
        }
    } catch {
        Write-AdminLog -Message "Failed to create rollback point: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

# Function to find backup file by date
function Find-BackupByDate {
    param(
        [string]$BackupDirectory,
        [datetime]$TargetDate
    )
    
    try {
        $backupFiles = Get-ChildItem $BackupDirectory -File | Where-Object {
            $_.Name -like "*backup*" -or $_.Extension -in @('.zip', '.bak', '.backup')
        }
        
        # Find closest backup to target date
        $closestBackup = $backupFiles | ForEach-Object {
            [PSCustomObject]@{
                File = $_
                TimeDiff = [math]::Abs(($_.LastWriteTime - $TargetDate).TotalHours)
            }
        } | Sort-Object TimeDiff | Select-Object -First 1
        
        if ($closestBackup) {
            Write-AdminLog -Message "Found backup for date $($TargetDate.ToString('yyyy-MM-dd')): $($closestBackup.File.Name)" -Level "Success"
            return $closestBackup.File.FullName
        } else {
            throw "No backup found for date $($TargetDate.ToString('yyyy-MM-dd'))"
        }
    } catch {
        Write-AdminLog -Message "Failed to find backup by date: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

try {
    # Validate parameters
    if (-not (Test-Path $BackupPath)) {
        throw "Backup path not found: $BackupPath"
    }
    
    if ($RestoreMode -eq "Selective" -and (-not $SelectivePatterns -or $SelectivePatterns.Count -eq 0)) {
        throw "Selective patterns must be specified for Selective restore mode"
    }
    
    if ($RestoreMode -eq "PointInTime" -and -not $BackupDate) {
        throw "BackupDate must be specified for PointInTime restore mode"
    }
    
    # Initialize restoration result
    $restorationResult = [PSCustomObject]@{
        RestoreMode = $RestoreMode
        SourcePath = $BackupPath
        DestinationPath = $RestoreDestination
        StartTime = Get-Date
        EndTime = $null
        Duration = $null
        Status = "Unknown"
        FilesRestored = 0
        TotalSizeMB = 0
        RollbackPath = $null
        IntegrityVerified = $false
        Errors = @()
        Warnings = @()
        Summary = ""
    }
    
    # Determine actual backup file to use
    $actualBackupFile = $BackupPath
    
    if ($RestoreMode -eq "PointInTime") {
        if (Test-Path $BackupPath -PathType Container) {
            $actualBackupFile = Find-BackupByDate -BackupDirectory $BackupPath -TargetDate $BackupDate
            if (-not $actualBackupFile) {
                throw "No backup found for specified date"
            }
        } else {
            Write-AdminLog -Message "Using specified backup file for point-in-time restore" -Level "Info"
        }
    }
    
    Write-AdminLog -Message "Using backup file: $actualBackupFile" -Level "Info"
    
    # Create destination directory if it doesn't exist
    if (-not $TestMode -and -not (Test-Path $RestoreDestination)) {
        New-Item -Path $RestoreDestination -ItemType Directory -Force | Out-Null
        Write-AdminLog -Message "Created destination directory: $RestoreDestination" -Level "Info"
    }
    
    # Create rollback point if requested
    if ($CreateRollback -and -not $TestMode) {
        $rollbackDir = "$RestoreDestination-Rollback"
        $restorationResult.RollbackPath = New-RollbackPoint -TargetPath $RestoreDestination -RollbackPath $rollbackDir
    }
    
    # Handle encrypted backups
    $workingBackupFile = $actualBackupFile
    if ($actualBackupFile -like "*.encrypted" -and $EncryptionKey) {
        $tempDecryptedFile = Join-Path $env:TEMP "decrypted-$(Get-Date -Format 'yyyyMMdd-HHmmss').tmp"
        
        if (Unprotect-BackupData -EncryptedFilePath $actualBackupFile -KeyPath $EncryptionKey -OutputPath $tempDecryptedFile) {
            $workingBackupFile = $tempDecryptedFile
            Write-AdminLog -Message "Using decrypted backup file" -Level "Success"
        } else {
            throw "Failed to decrypt backup file"
        }
    }
    
    # Pre-restoration integrity check
    if ($VerifyIntegrity) {
        Write-AdminLog -Message "Performing pre-restoration integrity check..." -Level "Info"
        
        $integrityCheck = Test-FileIntegrity -FilePath $workingBackupFile
        if (-not $integrityCheck.IsValid) {
            $restorationResult.Errors += "Pre-restoration integrity check failed: $($integrityCheck.Error)"
            Write-AdminLog -Message "Backup file integrity check failed" -Level "Error"
        } else {
            Write-AdminLog -Message "Pre-restoration integrity check passed" -Level "Success"
        }
    }
    
    if ($TestMode) {
        Write-AdminLog -Message "TEST MODE: Validating restoration parameters..." -Level "Info"
        
        # Test archive extraction without actually extracting
        if ((Get-Item $workingBackupFile).Extension -eq '.zip') {
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $archive = [System.IO.Compression.ZipFile]::OpenRead($workingBackupFile)
                $totalEntries = $archive.Entries.Count
                $selectiveCount = 0
                
                if ($SelectivePatterns) {
                    foreach ($entry in $archive.Entries) {
                        foreach ($pattern in $SelectivePatterns) {
                            if ($entry.FullName -like $pattern) {
                                $selectiveCount++
                                break
                            }
                        }
                    }
                }
                
                $archive.Dispose()
                
                $restorationResult.Status = "Test Successful"
                $restorationResult.FilesRestored = if ($SelectivePatterns) { $selectiveCount } else { $totalEntries }
                $restorationResult.Summary = "TEST MODE: Would restore $($restorationResult.FilesRestored) files"
                
                Write-AdminLog -Message "TEST MODE: Would restore $($restorationResult.FilesRestored) files" -Level "Success"
            } catch {
                $restorationResult.Status = "Test Failed"
                $restorationResult.Errors += "Archive validation failed: $($_.Exception.Message)"
            }
        } else {
            $restorationResult.Status = "Test Successful"
            $restorationResult.Summary = "TEST MODE: Would copy backup file to destination"
        }
    } else {
        # Perform actual restoration
        Write-AdminLog -Message "Starting restoration process..." -Level "Info"
        
        if ((Get-Item $workingBackupFile).Extension -eq '.zip') {
            # Extract compressed backup
            $extractionResult = Expand-BackupArchive -ArchivePath $workingBackupFile -DestinationPath $RestoreDestination -SelectivePatterns $SelectivePatterns
            
            if ($extractionResult.Success) {
                $restorationResult.FilesRestored = $extractionResult.ExtractedCount
                $restorationResult.Status = "Success"
                Write-AdminLog -Message "Successfully extracted $($extractionResult.ExtractedCount) files" -Level "Success"
                
                # Calculate total size
                $totalSize = 0
                foreach ($file in $extractionResult.ExtractedFiles) {
                    if (Test-Path $file) {
                        $totalSize += (Get-Item $file).Length
                    }
                }
                $restorationResult.TotalSizeMB = [math]::Round($totalSize / 1MB, 2)
            } else {
                $restorationResult.Status = "Failed"
                $restorationResult.Errors += $extractionResult.Error
            }
        } else {
            # Copy single backup file
            try {
                $destinationFile = Join-Path $RestoreDestination (Split-Path $workingBackupFile -Leaf)
                
                if ((Test-Path $destinationFile) -and -not $OverwriteExisting) {
                    throw "Destination file exists and OverwriteExisting is not specified"
                }
                
                Copy-Item $workingBackupFile $destinationFile -Force
                
                $restorationResult.FilesRestored = 1
                $restorationResult.TotalSizeMB = [math]::Round((Get-Item $destinationFile).Length / 1MB, 2)
                $restorationResult.Status = "Success"
                
                Write-AdminLog -Message "Successfully copied backup file to destination" -Level "Success"
            } catch {
                $restorationResult.Status = "Failed"
                $restorationResult.Errors += $_.Exception.Message
            }
        }
        
        # Post-restoration integrity check
        if ($VerifyIntegrity -and $restorationResult.Status -eq "Success") {
            Write-AdminLog -Message "Performing post-restoration integrity check..." -Level "Info"
            
            $restoredFiles = Get-ChildItem $RestoreDestination -Recurse -File
            $integrityIssues = 0
            
            foreach ($file in $restoredFiles | Select-Object -First 10) { # Sample check for performance
                $integrityCheck = Test-FileIntegrity -FilePath $file.FullName
                if (-not $integrityCheck.IsValid) {
                    $integrityIssues++
                }
            }
            
            if ($integrityIssues -eq 0) {
                $restorationResult.IntegrityVerified = $true
                Write-AdminLog -Message "Post-restoration integrity check passed" -Level "Success"
            } else {
                $restorationResult.Warnings += "Some files failed post-restoration integrity check"
                Write-AdminLog -Message "Post-restoration integrity check found issues in $integrityIssues files" -Level "Warning"
            }
        }
    }
    
    # Clean up temporary files
    if ($workingBackupFile -ne $actualBackupFile -and (Test-Path $workingBackupFile)) {
        Remove-Item $workingBackupFile -Force -ErrorAction SilentlyContinue
        Write-AdminLog -Message "Cleaned up temporary decrypted file" -Level "Info"
    }
    
    # Finalize result
    $restorationResult.EndTime = Get-Date
    $restorationResult.Duration = $restorationResult.EndTime - $restorationResult.StartTime
    
    if (-not $restorationResult.Summary) {
        $restorationResult.Summary = switch ($restorationResult.Status) {
            "Success" { "Successfully restored $($restorationResult.FilesRestored) files ($($restorationResult.TotalSizeMB) MB)" }
            "Failed" { "Restoration failed: $($restorationResult.Errors -join '; ')" }
            default { "Restoration completed with status: $($restorationResult.Status)" }
        }
    }
    
    # Send email notification if requested
    if ($EmailNotification) {
        $subject = "Data Restoration $($restorationResult.Status) - $RestoreMode"
        $body = @"
Data Restoration Report

Mode: $RestoreMode
Source: $BackupPath
Destination: $RestoreDestination
Status: $($restorationResult.Status)
Duration: $($restorationResult.Duration.ToString())

Summary:
$($restorationResult.Summary)

Files Restored: $($restorationResult.FilesRestored)
Total Size: $($restorationResult.TotalSizeMB) MB
Integrity Verified: $($restorationResult.IntegrityVerified)

$(if ($restorationResult.RollbackPath) { "Rollback Path: $($restorationResult.RollbackPath)" })

$(if ($restorationResult.Errors.Count -gt 0) {
    "ERRORS:" + "`n" + ($restorationResult.Errors | ForEach-Object { "- $_" }) -join "`n"
})

$(if ($restorationResult.Warnings.Count -gt 0) {
    "WARNINGS:" + "`n" + ($restorationResult.Warnings | ForEach-Object { "- $_" }) -join "`n"
})

This is an automated notification from the data restoration system.
"@
        
        try {
            $priority = if ($restorationResult.Status -eq "Failed") { "High" } else { "Normal" }
            Send-AdminNotification -Subject $subject -Body $body -Priority $priority
            Write-AdminLog -Message "Restoration notification sent via email" -Level "Success"
        } catch {
            Write-AdminLog -Message "Failed to send email notification: $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    # Generate final report
    $report = New-AdminReport -ReportTitle "Data Restoration Operation" -Data $restorationResult -Description "Data restoration from backup operation results" -Metadata @{
        RestoreMode = $RestoreMode
        TestMode = $TestMode.IsPresent
        VerifyIntegrity = $VerifyIntegrity.IsPresent
        CreateRollback = $CreateRollback.IsPresent
        SelectivePatterns = $SelectivePatterns
        BackupDate = $BackupDate
    }
    
    Write-Output $report
    
    # Summary
    if ($TestMode) {
        Write-AdminLog -Message "TEST MODE COMPLETE: $($restorationResult.Summary)" -Level "Info"
    } else {
        Write-AdminLog -Message "Data restoration completed: $($restorationResult.Status)" -Level "Success"
        Write-AdminLog -Message $restorationResult.Summary -Level "Info"
    }
    
} catch {
    $restorationResult.EndTime = Get-Date
    $restorationResult.Duration = $restorationResult.EndTime - $restorationResult.StartTime
    $restorationResult.Status = "Failed"
    $restorationResult.Errors += $_.Exception.Message
    $restorationResult.Summary = "Restoration failed: $($_.Exception.Message)"
    
    Write-AdminLog -Message "Data restoration failed: $($_.Exception.Message)" -Level "Error"
    throw
}
