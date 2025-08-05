---
uid: api.psadmincore.test-adminparameter
name: Test-AdminParameter
---

# Test-AdminParameter

## Synopsis
Validates parameters using common validation patterns for administrative tasks.

## Description
This function provides standardized parameter validation for administrative scripts, ensuring data integrity and security. It supports common validation types including empty value checks, email format validation, and other patterns commonly needed in automation scenarios.

Using centralized validation ensures consistent data quality across all administrative scripts and reduces the risk of errors from invalid input data.

## Syntax
```powershell
Test-AdminParameter [-Value] <Object> [[-Type] <String>] [<CommonParameters>]
```

## Parameters

### -Value
The value to validate. This parameter is mandatory.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| Object | true | 1 | none |

### -Type
The type of validation to perform. Supported types:
- NotEmpty: Validates that the value is not null, empty, or whitespace
- Email: Validates that the value is a properly formatted email address
- Domain: Validates that the value is a valid domain name format
- UPN: Validates that the value is a valid User Principal Name format

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 2 | NotEmpty |

**Valid values:** NotEmpty, Email, Domain, UPN

## Outputs
**System.Boolean**

Returns `$true` if the value passes validation, otherwise `$false`.

## Examples

### Example 1: Email validation
```powershell
PS C:\> Test-AdminParameter -Value "john.doe@company.com" -Type Email
```

This command validates that the provided value is a properly formatted email address. Returns $true if valid, $false otherwise.

### Example 2: Input validation in scripts
```powershell
PS C:\> if (-not (Test-AdminParameter -Value $userInput -Type NotEmpty)) {
    Write-Error "Input cannot be empty"
    return
}
```

This command demonstrates input validation at the beginning of a script to ensure required parameters are provided before proceeding with administrative operations.

## Notes
- **Author:** Automation Team
- **Version:** 1.2.0
- **Prerequisites:** No special prerequisites required for basic validation patterns.

## Related Links
- [about_Regular_Expressions](https://docs.microsoft.com/powershell/module/microsoft.powershell.core/about/about_regular_expressions)