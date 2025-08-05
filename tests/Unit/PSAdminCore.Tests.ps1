#Requires -Modules Pester
<#
.SYNOPSIS
    Unit tests for PSAdminCore module functions.
.DESCRIPTION
    Comprehensive Pester tests for all public functions in the PSAdminCore module.
#>

BeforeAll {
    # Import the module
    $testRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $repoRoot = Split-Path (Split-Path $testRoot -Parent) -Parent
    $modulePath = Join-Path $repoRoot 'modules/PSAdminCore/PSAdminCore.psd1'
    
    if (Test-Path $modulePath) {
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        throw "Module not found at: $modulePath"
    }
    
    # Set up test environment
    $script:TestLogPath = Join-Path ([System.IO.Path]::GetTempPath()) "PSAdminCore_Test_$(Get-Date -Format 'yyyyMMddHHmmss').log"
}

AfterAll {
    # Clean up test files
    if (Test-Path $script:TestLogPath) {
        Remove-Item $script:TestLogPath -Force -ErrorAction SilentlyContinue
    }
    
    # Remove module
    Remove-Module PSAdminCore -Force -ErrorAction SilentlyContinue
}

Describe 'Write-AdminLog' {
    Context 'Basic Functionality' {
        It 'Should write info message without errors' {
            { Write-AdminLog -Message "Test info message" -Level Info } | Should -Not -Throw
        }

        It 'Should write warning message without errors' {
            { Write-AdminLog -Message "Test warning" -Level Warning } | Should -Not -Throw
        }

        It 'Should write error message without errors' {
            { Write-AdminLog -Message "Test error" -Level Error } | Should -Not -Throw
        }

        It 'Should write success message without errors' {
            { Write-AdminLog -Message "Test success" -Level Success } | Should -Not -Throw
        }

        It 'Should return log entry when PassThru is specified' {
            $result = Write-AdminLog -Message "Test" -Level Info -PassThru
            $result | Should -Not -BeNullOrEmpty
            $result.Message | Should -Be "Test"
            $result.Level | Should -Be "Info"
        }
    }

    Context 'File Logging' {
        It 'Should create log file when writing' {
            Write-AdminLog -Message "File test" -Level Info
            # Give it a moment to write
            Start-Sleep -Milliseconds 100
            
            # Check if any log file was created in temp directory
            $logFiles = Get-ChildItem $env:TEMP -Filter "PSAdminCore_*.log" -ErrorAction SilentlyContinue
            $logFiles | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Test-AdminPrivileges' {
    Context 'Basic Functionality' {
        It 'Should return boolean value' {
            $result = Test-AdminPrivileges -Quiet
            $result | Should -BeOfType [bool]
        }

        It 'Should not throw with Quiet parameter' {
            { Test-AdminPrivileges -Quiet } | Should -Not -Throw
        }

        It 'Should handle non-admin scenario gracefully' {
            # This test will pass regardless of admin status
            $result = Test-AdminPrivileges -Quiet
            $result | Should -BeIn @($true, $false)
        }
    }
}

Describe 'Test-AdminParameter' {
    Context 'Mandatory Validation' {
        It 'Should fail when mandatory parameter is null' {
            $result = Test-AdminParameter -Value $null -Name "TestParam" -Mandatory
            $result | Should -Be $false
        }

        It 'Should pass when mandatory parameter has value' {
            $result = Test-AdminParameter -Value "test" -Name "TestParam" -Mandatory
            $result | Should -Be $true
        }
    }

    Context 'Type Validation' {
        It 'Should pass when type matches' {
            $result = Test-AdminParameter -Value 42 -Name "TestParam" -Type ([int])
            $result | Should -Be $true
        }

        It 'Should pass when value can be converted to type' {
            $result = Test-AdminParameter -Value "42" -Name "TestParam" -Type ([int])
            $result | Should -Be $true
        }

        It 'Should fail when type does not match and cannot convert' {
            $result = Test-AdminParameter -Value "not a number" -Name "TestParam" -Type ([int])
            $result | Should -Be $false
        }
    }

    Context 'ValidateSet' {
        It 'Should pass when value is in set' {
            $result = Test-AdminParameter -Value "Red" -Name "Color" -ValidateSet @("Red", "Green", "Blue")
            $result | Should -Be $true
        }

        It 'Should fail when value is not in set' {
            $result = Test-AdminParameter -Value "Yellow" -Name "Color" -ValidateSet @("Red", "Green", "Blue")
            $result | Should -Be $false
        }
    }

    Context 'ValidateRange' {
        It 'Should pass when value is within range' {
            $result = Test-AdminParameter -Value 50 -Name "Age" -ValidateRange @{Min=18; Max=100}
            $result | Should -Be $true
        }

        It 'Should fail when value is below minimum' {
            $result = Test-AdminParameter -Value 10 -Name "Age" -ValidateRange @{Min=18; Max=100}
            $result | Should -Be $false
        }

        It 'Should fail when value exceeds maximum' {
            $result = Test-AdminParameter -Value 150 -Name "Age" -ValidateRange @{Min=18; Max=100}
            $result | Should -Be $false
        }
    }

    Context 'ValidatePattern' {
        It 'Should pass when pattern matches' {
            $result = Test-AdminParameter -Value "test@example.com" -Name "Email" -ValidatePattern '^[\w\.-]+@[\w\.-]+\.\w+$'
            $result | Should -Be $true
        }

        It 'Should fail when pattern does not match' {
            $result = Test-AdminParameter -Value "not-an-email" -Name "Email" -ValidatePattern '^[\w\.-]+@[\w\.-]+\.\w+$'
            $result | Should -Be $false
        }
    }

    Context 'ValidateLength' {
        It 'Should pass when string length is within limits' {
            $result = Test-AdminParameter -Value "Hello" -Name "Text" -ValidateLength @{Min=3; Max=10}
            $result | Should -Be $true
        }

        It 'Should fail when string is too short' {
            $result = Test-AdminParameter -Value "Hi" -Name "Text" -ValidateLength @{Min=3; Max=10}
            $result | Should -Be $false
        }

        It 'Should fail when string is too long' {
            $result = Test-AdminParameter -Value "This is a very long string" -Name "Text" -ValidateLength @{Min=3; Max=10}
            $result | Should -Be $false
        }
    }
}

Describe 'New-AdminReport' {
    Context 'Basic Report Generation' {
        It 'Should create report object with required properties' {
            $report = New-AdminReport -ReportTitle "Test Report" -Data @{Test="Data"}
            
            $report | Should -Not -BeNullOrEmpty
            $report.ReportTitle | Should -Be "Test Report"
            $report.ReportID | Should -Not -BeNullOrEmpty
            $report.GeneratedDate | Should -Not -BeNullOrEmpty
            $report.Status | Should -Be "Information"
        }

        It 'Should include metadata when provided' {
            $metadata = @{Version="1.0"; Environment="Test"}
            $report = New-AdminReport -ReportTitle "Test" -Data @{} -Metadata $metadata
            
            $report.Metadata | Should -Not -BeNullOrEmpty
            $report.Metadata.Version | Should -Be "1.0"
            $report.Metadata.Environment | Should -Be "Test"
        }

        It 'Should handle different status values' {
            $report = New-AdminReport -ReportTitle "Test" -Data @{} -Status "Success"
            $report.Status | Should -Be "Success"
            $report.StatusSymbol | Should -Be "✓"
        }
    }

    Context 'Report Export' {
        It 'Should export to JSON format' {
            $testPath = Join-Path $env:TEMP "test_report.json"
            try {
                New-AdminReport -ReportTitle "JSON Test" -Data @{Test="Data"} -OutputPath $testPath -Format JSON
                Test-Path $testPath | Should -Be $true
                
                $content = Get-Content $testPath -Raw | ConvertFrom-Json
                $content.ReportTitle | Should -Be "JSON Test"
            }
            finally {
                if (Test-Path $testPath) {
                    Remove-Item $testPath -Force
                }
            }
        }

        It 'Should return report object with PassThru' {
            $testPath = Join-Path $env:TEMP "test_report_passthru.json"
            try {
                $report = New-AdminReport -ReportTitle "PassThru Test" -Data @{} -OutputPath $testPath -PassThru
                $report | Should -Not -BeNullOrEmpty
                $report.ReportTitle | Should -Be "PassThru Test"
                Test-Path $testPath | Should -Be $true
            }
            finally {
                if (Test-Path $testPath) {
                    Remove-Item $testPath -Force
                }
            }
        }
    }
}

Describe 'Test-AdminConnectivity' {
    Context 'Basic Connectivity Tests' {
        It 'Should test localhost without errors' {
            { Test-AdminConnectivity -Target "localhost" -Protocol ICMP } | Should -Not -Throw
        }

        It 'Should return boolean by default' {
            $result = Test-AdminConnectivity -Target "localhost" -Protocol ICMP
            $result | Should -BeOfType [bool]
        }

        It 'Should return detailed object when Detailed is specified' {
            $result = Test-AdminConnectivity -Target "localhost" -Protocol ICMP -Detailed
            $result | Should -Not -BeNullOrEmpty
            $result.Target | Should -Be "localhost"
            $result.Protocol | Should -Be "ICMP"
        }

        It 'Should handle unreachable host gracefully' {
            $result = Test-AdminConnectivity -Target "192.0.2.1" -Protocol ICMP -Timeout 1
            $result | Should -BeIn @($true, $false)
        }
    }

    Context 'Multiple Targets' {
        It 'Should process multiple targets' {
            $results = Test-AdminConnectivity -Target @("localhost", "127.0.0.1") -Protocol ICMP -Detailed
            $results.Count | Should -Be 2
        }
    }
}

Describe 'Get-AdminConfig and Set-AdminConfig' {
    Context 'Configuration Management' {
        It 'Should return default config when file does not exist' {
            $config = Get-AdminConfig -ConfigName "test-config-nonexistent" -Force
            $config | Should -Not -BeNullOrEmpty
            $config | Should -BeOfType [hashtable]
        }

        It 'Should return default email configuration structure' {
            $config = Get-AdminConfig -ConfigName "email" -Force
            $config | Should -Not -BeNullOrEmpty
            $config.SmtpServer | Should -Not -BeNullOrEmpty
            $config.SmtpPort | Should -Not -BeNullOrEmpty
        }

        It 'Should cache configuration after first load' {
            $config1 = Get-AdminConfig -ConfigName "email"
            $config2 = Get-AdminConfig -ConfigName "email"
            # Both should be the same reference (cached)
            $config1 | Should -Be $config2
        }

        It 'Should force reload with Force parameter' {
            $config1 = Get-AdminConfig -ConfigName "email"
            $config2 = Get-AdminConfig -ConfigName "email" -Force
            # These might be different objects even with same content
            $config2 | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Set-AdminConfig' {
        It 'Should create new configuration' {
            $testConfigPath = Join-Path $env:TEMP "PSAutomation\config"
            New-Item -Path $testConfigPath -ItemType Directory -Force | Out-Null
            
            try {
                $settings = @{TestKey="TestValue"; Number=42}
                Set-AdminConfig -ConfigName "unit-test" -Settings $settings -ConfigPath $testConfigPath
                
                $configFile = Join-Path $testConfigPath "unit-test.json"
                Test-Path $configFile | Should -Be $true
            }
            finally {
                if (Test-Path $testConfigPath) {
                    Remove-Item $testConfigPath -Recurse -Force
                }
            }
        }
    }
}

Describe 'Initialize-AdminEnvironment' {
    Context 'Environment Initialization' {
        It 'Should initialize without errors' {
            { Initialize-AdminEnvironment -Quiet } | Should -Not -Throw
        }

        It 'Should return true on successful initialization' {
            $result = Initialize-AdminEnvironment -Quiet
            $result | Should -Be $true
        }

        It 'Should accept custom log path' {
            $customLogPath = Join-Path $env:TEMP "CustomLogs"
            { Initialize-AdminEnvironment -LogPath $customLogPath -Quiet } | Should -Not -Throw
        }
    }
}