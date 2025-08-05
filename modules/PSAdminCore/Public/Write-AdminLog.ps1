function Write-AdminLog {
    <#
    .SYNOPSIS
        Writes a structured log message with severity levels and formatting.
    .DESCRIPTION
        Provides centralized logging functionality with support for different severity levels,
        automatic timestamping, and both console and file output. Maintains a daily log file
        and provides color-coded console output based on severity.
    .PARAMETER Message
        The log message to write.
    .PARAMETER Level
        The severity level of the message. Valid values: Info, Warning, Error, Success, Debug, Verbose.
    .PARAMETER NoConsole
        If specified, suppresses console output and only writes to the log file.
    .PARAMETER NoFile
        If specified, suppresses file output and only writes to the console.
    .PARAMETER PassThru
        If specified, returns the log entry as an object.
    .EXAMPLE
        Write-AdminLog -Message "Starting backup process" -Level "Info"
        Writes an informational message to both console and log file.
    .EXAMPLE
        Write-AdminLog -Message "Failed to connect to server" -Level "Error"
        Writes an error message with red console highlighting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug', 'Verbose')]
        [string]$Level = 'Info',

        [Parameter(Mandatory = $false)]
        [switch]$NoConsole,

        [Parameter(Mandatory = $false)]
        [switch]$NoFile,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    begin {
        # Define color mapping for console output
        $colorMap = @{
            'Info'    = 'Cyan'
            'Warning' = 'Yellow'
            'Error'   = 'Red'
            'Success' = 'Green'
            'Debug'   = 'Gray'
            'Verbose' = 'DarkGray'
        }

        # Define emoji/symbols for each level
        $symbolMap = @{
            'Info'    = '[i]'
            'Warning' = '[!]'
            'Error'   = '[X]'
            'Success' = '[✓]'
            'Debug'   = '[D]'
            'Verbose' = '[V]'
        }
    }

    process {
        # Create timestamp
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        
        # Get calling function name for context
        $callingFunction = (Get-PSCallStack)[1].Command
        if ($callingFunction -eq '<ScriptBlock>') {
            $callingFunction = 'Script'
        }

        # Create log entry object
        $logEntry = [PSCustomObject]@{
            Timestamp = $timestamp
            Level     = $Level
            Function  = $callingFunction
            Message   = $Message
            User      = $env:USERNAME
            Computer  = $env:COMPUTERNAME
        }

        # Console output
        if (-not $NoConsole) {
            $consoleMessage = "$($symbolMap[$Level]) [$timestamp] $Message"
            
            # Use appropriate console output based on level
            switch ($Level) {
                'Error' {
                    Write-Host $consoleMessage -ForegroundColor $colorMap[$Level]
                }
                'Warning' {
                    Write-Warning $Message
                }
                'Verbose' {
                    Write-Verbose $Message -Verbose:$true
                }
                'Debug' {
                    Write-Debug $Message -Debug:$true
                }
                default {
                    Write-Host $consoleMessage -ForegroundColor $colorMap[$Level]
                }
            }
        }

        # File output
        if (-not $NoFile) {
            try {
                # Ensure log directory exists
                $logDir = Split-Path $script:LogPath -Parent
                if (-not (Test-Path $logDir)) {
                    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
                }

                # Create formatted log line
                $logLine = "$timestamp`t$Level`t$callingFunction`t$Message`t$($env:USERNAME)`t$($env:COMPUTERNAME)"
                
                # Append to log file
                Add-Content -Path $script:LogPath -Value $logLine -Encoding UTF8 -ErrorAction Stop
            }
            catch {
                # If file logging fails, at least try to notify via console
                if (-not $NoConsole) {
                    Write-Warning "Failed to write to log file: $_"
                }
            }
        }

        # Return log entry if requested
        if ($PassThru) {
            return $logEntry
        }
    }
}