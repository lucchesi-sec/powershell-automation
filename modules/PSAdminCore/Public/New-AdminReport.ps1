function New-AdminReport {
    <#
    .SYNOPSIS
        Creates a standardized report object for consistent reporting across scripts.
    .DESCRIPTION
        Generates a structured report object with consistent formatting, metadata,
        and export capabilities. Supports multiple output formats and automatic
        file generation.
    .PARAMETER ReportTitle
        The title of the report.
    .PARAMETER Data
        The main data/content for the report.
    .PARAMETER Description
        Optional description or summary of the report.
    .PARAMETER Metadata
        Additional metadata as a hashtable (e.g., parameters used, environment info).
    .PARAMETER Status
        Status of the operation: Success, Warning, Error, or Information.
    .PARAMETER OutputPath
        If specified, saves the report to this path.
    .PARAMETER Format
        Output format when saving: JSON, XML, CSV, or HTML.
    .PARAMETER PassThru
        Returns the report object even when saving to file.
    .EXAMPLE
        $report = New-AdminReport -ReportTitle "Backup Status" -Data $backupResults -Status Success
    .EXAMPLE
        New-AdminReport -ReportTitle "User Audit" -Data $auditData -OutputPath "C:\Reports\audit.json" -Format JSON
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportTitle,

        [Parameter(Mandatory = $false)]
        [object]$Data,

        [Parameter(Mandatory = $false)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [hashtable]$Metadata = @{},

        [Parameter(Mandatory = $false)]
        [ValidateSet('Success', 'Warning', 'Error', 'Information')]
        [string]$Status = 'Information',

        [Parameter(Mandatory = $false)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'XML', 'CSV', 'HTML')]
        [string]$Format = 'JSON',

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    try {
        Write-AdminLog -Message "Creating report: $ReportTitle" -Level Info

        # Create base report structure
        $report = [PSCustomObject]@{
            ReportTitle     = $ReportTitle
            ReportID        = [guid]::NewGuid().ToString()
            GeneratedDate   = Get-Date
            GeneratedBy     = $env:USERNAME
            ComputerName    = $env:COMPUTERNAME
            Domain          = $env:USERDNSDOMAIN
            Status          = $Status
            Description     = $Description
            ExecutionTime   = [System.Diagnostics.Stopwatch]::StartNew()
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            Data            = $Data
            Metadata        = $Metadata
            Summary         = @{}
        }

        # Add summary statistics based on data type
        if ($Data) {
            $report.Summary = @{
                DataType = $Data.GetType().Name
            }

            if ($Data -is [Array] -or $Data -is [System.Collections.IEnumerable]) {
                $dataArray = @($Data)
                $report.Summary['ItemCount'] = $dataArray.Count
                
                if ($dataArray.Count -gt 0) {
                    # Get property names from first item
                    $firstItem = $dataArray[0]
                    if ($firstItem.PSObject.Properties) {
                        $report.Summary['Properties'] = @($firstItem.PSObject.Properties.Name)
                    }
                }
            }
            elseif ($Data -is [Hashtable]) {
                $report.Summary['KeyCount'] = $Data.Keys.Count
                $report.Summary['Keys'] = @($Data.Keys)
            }
        }

        # Stop execution timer
        $report.ExecutionTime.Stop()
        $executionSeconds = [Math]::Round($report.ExecutionTime.Elapsed.TotalSeconds, 2)
        $report.ExecutionTime = "$executionSeconds seconds"

        # Add status icon/symbol
        $statusSymbol = switch ($Status) {
            'Success'     { '✓' }
            'Warning'     { '⚠' }
            'Error'       { '✗' }
            'Information' { 'ℹ' }
        }
        $report | Add-Member -NotePropertyName 'StatusSymbol' -NotePropertyValue $statusSymbol

        # Save to file if OutputPath specified
        if ($OutputPath) {
            Write-AdminLog -Message "Saving report to: $OutputPath" -Level Info

            # Ensure directory exists
            $outputDir = Split-Path $OutputPath -Parent
            if ($outputDir -and -not (Test-Path $outputDir)) {
                New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
            }

            switch ($Format) {
                'JSON' {
                    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
                }
                'XML' {
                    $report | Export-Clixml -Path $OutputPath
                }
                'CSV' {
                    if ($Data -is [Array]) {
                        $Data | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                    } else {
                        $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                    }
                }
                'HTML' {
                    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>$($report.ReportTitle)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { border-bottom: 2px solid #0078d4; padding-bottom: 10px; margin-bottom: 20px; }
        h1 { color: #0078d4; margin: 0; }
        .status { display: inline-block; padding: 5px 10px; border-radius: 4px; font-weight: bold; margin-left: 10px; }
        .status.Success { background: #4caf50; color: white; }
        .status.Warning { background: #ff9800; color: white; }
        .status.Error { background: #f44336; color: white; }
        .status.Information { background: #2196f3; color: white; }
        .metadata { background: #f9f9f9; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .metadata dt { font-weight: bold; display: inline-block; width: 150px; }
        .metadata dd { display: inline; margin: 0; }
        .data { margin-top: 20px; }
        pre { background: #f5f5f5; padding: 15px; border-radius: 4px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #0078d4; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>$($report.StatusSymbol) $($report.ReportTitle) <span class="status $($report.Status)">$($report.Status)</span></h1>
        </div>
        
        <div class="metadata">
            <dl>
                <dt>Generated:</dt><dd>$($report.GeneratedDate)</dd><br>
                <dt>Generated By:</dt><dd>$($report.GeneratedBy)</dd><br>
                <dt>Computer:</dt><dd>$($report.ComputerName)</dd><br>
                <dt>Execution Time:</dt><dd>$($report.ExecutionTime)</dd><br>
                <dt>Report ID:</dt><dd>$($report.ReportID)</dd>
            </dl>
        </div>

        $(if ($Description) { "<div class='description'><h2>Description</h2><p>$Description</p></div>" })

        <div class="data">
            <h2>Report Data</h2>
            $(if ($report.Summary.ItemCount) { "<p>Total Items: $($report.Summary.ItemCount)</p>" })
            <pre>$($Data | ConvertTo-Json -Depth 5)</pre>
        </div>

        $(if ($Metadata.Count -gt 0) {
            "<div class='metadata'><h2>Additional Metadata</h2><pre>$($Metadata | ConvertTo-Json -Depth 3)</pre></div>"
        })
    </div>
</body>
</html>
"@
                    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
                }
            }

            Write-AdminLog -Message "Report saved successfully as $Format" -Level Success
        }

        # Return report object if no output path specified or PassThru is set
        if (-not $OutputPath -or $PassThru) {
            return $report
        }
    }
    catch {
        Write-AdminLog -Message "Failed to create report: $_" -Level Error
        throw
    }
}