function Test-AdminParameter {
    <#
    .SYNOPSIS
        Validates parameters against defined rules and constraints.
    .DESCRIPTION
        Provides comprehensive parameter validation including type checking, range validation,
        pattern matching, and custom validation rules. Helps ensure script inputs are safe
        and meet requirements before processing.
    .PARAMETER Value
        The value to validate.
    .PARAMETER Name
        The name of the parameter (for error messages).
    .PARAMETER Type
        Expected type of the parameter.
    .PARAMETER Mandatory
        Whether the parameter is required.
    .PARAMETER ValidateSet
        Array of valid values for the parameter.
    .PARAMETER ValidateRange
        Hashtable with Min and Max keys for numeric range validation.
    .PARAMETER ValidatePattern
        Regular expression pattern the value must match.
    .PARAMETER ValidateLength
        Hashtable with Min and Max keys for string length validation.
    .PARAMETER ValidatePath
        Validates that the path exists. Values: 'File', 'Directory', 'Any'.
    .PARAMETER ValidateScript
        Script block for custom validation logic.
    .EXAMPLE
        Test-AdminParameter -Value $email -Name "EmailAddress" -ValidatePattern '^[\w\.-]+@[\w\.-]+\.\w+$'
    .EXAMPLE
        Test-AdminParameter -Value $age -Name "Age" -Type [int] -ValidateRange @{Min=18; Max=100}
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [Type]$Type,

        [Parameter(Mandatory = $false)]
        [switch]$Mandatory,

        [Parameter(Mandatory = $false)]
        [array]$ValidateSet,

        [Parameter(Mandatory = $false)]
        [hashtable]$ValidateRange,

        [Parameter(Mandatory = $false)]
        [string]$ValidatePattern,

        [Parameter(Mandatory = $false)]
        [hashtable]$ValidateLength,

        [Parameter(Mandatory = $false)]
        [ValidateSet('File', 'Directory', 'Any')]
        [string]$ValidatePath,

        [Parameter(Mandatory = $false)]
        [scriptblock]$ValidateScript
    )

    try {
        $errors = @()

        # Check mandatory
        if ($Mandatory -and ($null -eq $Value -or $Value -eq '')) {
            $errors += "Parameter '$Name' is mandatory but was not provided"
        }

        # If value is null and not mandatory, validation passes
        if ($null -eq $Value -and -not $Mandatory) {
            return $true
        }

        # Type validation
        if ($Type -and $Value -isnot $Type) {
            try {
                # Try to convert to the expected type
                $convertedValue = $Value -as $Type
                if ($null -eq $convertedValue) {
                    $errors += "Parameter '$Name' must be of type [$($Type.Name)] but received [$($Value.GetType().Name)]"
                } else {
                    # Update value for further validations
                    $Value = $convertedValue
                }
            }
            catch {
                $errors += "Parameter '$Name' cannot be converted to type [$($Type.Name)]: $_"
            }
        }

        # ValidateSet
        if ($ValidateSet -and $ValidateSet.Count -gt 0) {
            if ($Value -notin $ValidateSet) {
                $validValues = $ValidateSet -join ', '
                $errors += "Parameter '$Name' must be one of: $validValues (received: $Value)"
            }
        }

        # ValidateRange (for numeric values)
        if ($ValidateRange) {
            if ($Value -is [System.ValueType]) {
                if ($ValidateRange.ContainsKey('Min') -and $Value -lt $ValidateRange.Min) {
                    $errors += "Parameter '$Name' value $Value is below minimum of $($ValidateRange.Min)"
                }
                if ($ValidateRange.ContainsKey('Max') -and $Value -gt $ValidateRange.Max) {
                    $errors += "Parameter '$Name' value $Value exceeds maximum of $($ValidateRange.Max)"
                }
            } else {
                $errors += "Parameter '$Name' must be numeric for range validation"
            }
        }

        # ValidatePattern (regex)
        if ($ValidatePattern) {
            if ($Value -is [string]) {
                if ($Value -notmatch $ValidatePattern) {
                    $errors += "Parameter '$Name' value '$Value' does not match required pattern: $ValidatePattern"
                }
            } else {
                $errors += "Parameter '$Name' must be a string for pattern validation"
            }
        }

        # ValidateLength (for strings)
        if ($ValidateLength) {
            if ($Value -is [string]) {
                $length = $Value.Length
                if ($ValidateLength.ContainsKey('Min') -and $length -lt $ValidateLength.Min) {
                    $errors += "Parameter '$Name' length $length is below minimum of $($ValidateLength.Min)"
                }
                if ($ValidateLength.ContainsKey('Max') -and $length -gt $ValidateLength.Max) {
                    $errors += "Parameter '$Name' length $length exceeds maximum of $($ValidateLength.Max)"
                }
            } elseif ($Value -is [array]) {
                $count = $Value.Count
                if ($ValidateLength.ContainsKey('Min') -and $count -lt $ValidateLength.Min) {
                    $errors += "Parameter '$Name' count $count is below minimum of $($ValidateLength.Min)"
                }
                if ($ValidateLength.ContainsKey('Max') -and $count -gt $ValidateLength.Max) {
                    $errors += "Parameter '$Name' count $count exceeds maximum of $($ValidateLength.Max)"
                }
            } else {
                $errors += "Parameter '$Name' must be a string or array for length validation"
            }
        }

        # ValidatePath
        if ($ValidatePath) {
            if ($Value -is [string]) {
                $pathExists = Test-Path $Value
                $isFile = $pathExists -and (Get-Item $Value -ErrorAction SilentlyContinue).PSIsContainer -eq $false
                $isDirectory = $pathExists -and (Get-Item $Value -ErrorAction SilentlyContinue).PSIsContainer -eq $true

                switch ($ValidatePath) {
                    'File' {
                        if (-not $isFile) {
                            $errors += "Parameter '$Name' must be a valid file path: '$Value'"
                        }
                    }
                    'Directory' {
                        if (-not $isDirectory) {
                            $errors += "Parameter '$Name' must be a valid directory path: '$Value'"
                        }
                    }
                    'Any' {
                        if (-not $pathExists) {
                            $errors += "Parameter '$Name' must be a valid path: '$Value'"
                        }
                    }
                }
            } else {
                $errors += "Parameter '$Name' must be a string for path validation"
            }
        }

        # Custom validation script
        if ($ValidateScript) {
            try {
                $validationResult = & $ValidateScript $Value
                if (-not $validationResult) {
                    $errors += "Parameter '$Name' failed custom validation"
                }
            }
            catch {
                $errors += "Parameter '$Name' custom validation error: $_"
            }
        }

        # Report errors
        if ($errors.Count -gt 0) {
            foreach ($error in $errors) {
                Write-AdminLog -Message $error -Level Error
            }
            return $false
        }

        Write-AdminLog -Message "Parameter '$Name' validation passed" -Level Debug
        return $true
    }
    catch {
        Write-AdminLog -Message "Parameter validation failed for '$Name': $_" -Level Error
        return $false
    }
}