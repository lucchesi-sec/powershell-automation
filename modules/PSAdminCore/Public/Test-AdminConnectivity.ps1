function Test-AdminConnectivity {
    <#
    .SYNOPSIS
        Tests network connectivity to specified hosts or services.
    .DESCRIPTION
        Performs comprehensive connectivity testing including ping, port checks,
        DNS resolution, and service availability. Useful for pre-flight checks
        before running scripts that depend on network resources.
    .PARAMETER Target
        The target host, IP address, or URL to test.
    .PARAMETER Port
        Specific port to test (default: 443 for HTTPS, 445 for SMB, etc.).
    .PARAMETER Protocol
        Protocol to test: ICMP (ping), TCP, HTTP, HTTPS, SMB, WinRM, RDP.
    .PARAMETER Timeout
        Timeout in seconds for each test (default: 5).
    .PARAMETER Credential
        Credentials for authenticated connectivity tests.
    .PARAMETER Detailed
        Returns detailed test results instead of just boolean.
    .EXAMPLE
        Test-AdminConnectivity -Target "server01" -Protocol TCP -Port 445
    .EXAMPLE
        Test-AdminConnectivity -Target "https://api.example.com" -Protocol HTTPS -Detailed
    #>
    [CmdletBinding()]
    [OutputType([bool], [PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$Target,

        [Parameter(Mandatory = $false)]
        [int]$Port,

        [Parameter(Mandatory = $false)]
        [ValidateSet('ICMP', 'TCP', 'HTTP', 'HTTPS', 'SMB', 'WinRM', 'RDP', 'Auto')]
        [string]$Protocol = 'Auto',

        [Parameter(Mandatory = $false)]
        [int]$Timeout = 5,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [switch]$Detailed
    )

    begin {
        # Default ports for protocols
        $defaultPorts = @{
            'HTTP'   = 80
            'HTTPS'  = 443
            'SMB'    = 445
            'WinRM'  = 5985
            'RDP'    = 3389
            'TCP'    = 445
        }

        $results = @()
    }

    process {
        foreach ($t in $Target) {
            Write-AdminLog -Message "Testing connectivity to: $t" -Level Debug

            # Parse target (could be hostname, IP, or URL)
            $hostname = $t
            $testPort = $Port
            $testProtocol = $Protocol

            # Parse URL if provided
            if ($t -match '^https?://') {
                try {
                    $uri = [System.Uri]$t
                    $hostname = $uri.Host
                    if (-not $Port) {
                        $testPort = $uri.Port
                    }
                    if ($Protocol -eq 'Auto') {
                        $testProtocol = if ($uri.Scheme -eq 'https') { 'HTTPS' } else { 'HTTP' }
                    }
                }
                catch {
                    Write-AdminLog -Message "Failed to parse URL: $t" -Level Warning
                }
            }

            # Auto-detect protocol if not specified
            if ($testProtocol -eq 'Auto') {
                if ($testPort) {
                    $testProtocol = switch ($testPort) {
                        80 { 'HTTP' }
                        443 { 'HTTPS' }
                        445 { 'SMB' }
                        5985 { 'WinRM' }
                        5986 { 'WinRM' }
                        3389 { 'RDP' }
                        default { 'TCP' }
                    }
                } else {
                    $testProtocol = 'ICMP'
                }
            }

            # Set default port if not specified
            if (-not $testPort -and $defaultPorts.ContainsKey($testProtocol)) {
                $testPort = $defaultPorts[$testProtocol]
            }

            # Create result object
            $result = [PSCustomObject]@{
                Target       = $t
                Hostname     = $hostname
                Port         = $testPort
                Protocol     = $testProtocol
                DNSResolved  = $false
                IPAddress    = $null
                Reachable    = $false
                ResponseTime = $null
                ErrorMessage = $null
                Timestamp    = Get-Date
            }

            try {
                # DNS Resolution
                Write-AdminLog -Message "Resolving DNS for: $hostname" -Level Debug
                $dnsResult = Resolve-DnsName -Name $hostname -ErrorAction Stop
                $result.DNSResolved = $true
                $result.IPAddress = ($dnsResult | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1).IPAddress

                if (-not $result.IPAddress) {
                    $result.IPAddress = $hostname
                }

                # Perform connectivity test based on protocol
                switch ($testProtocol) {
                    'ICMP' {
                        Write-AdminLog -Message "Testing ICMP (ping) to $hostname" -Level Debug
                        $pingResult = Test-Connection -ComputerName $hostname -Count 1 -Quiet -ErrorAction Stop
                        $result.Reachable = $pingResult
                        
                        if ($pingResult) {
                            $detailedPing = Test-Connection -ComputerName $hostname -Count 1 -ErrorAction Stop
                            $result.ResponseTime = $detailedPing.ResponseTime
                        }
                    }

                    { $_ -in 'TCP', 'SMB', 'WinRM', 'RDP' } {
                        Write-AdminLog -Message "Testing TCP port $testPort on $hostname" -Level Debug
                        
                        $tcpClient = New-Object System.Net.Sockets.TcpClient
                        $connectTask = $tcpClient.ConnectAsync($hostname, $testPort)
                        $waitResult = $connectTask.Wait([TimeSpan]::FromSeconds($Timeout))
                        
                        if ($waitResult -and -not $connectTask.IsFaulted) {
                            $result.Reachable = $true
                            $result.ResponseTime = [math]::Round(($connectTask.IsCompletedSuccessfully), 2)
                            $tcpClient.Close()
                        } else {
                            $result.Reachable = $false
                            if ($connectTask.Exception) {
                                $result.ErrorMessage = $connectTask.Exception.InnerException.Message
                            } else {
                                $result.ErrorMessage = "Connection timeout"
                            }
                        }
                        $tcpClient.Dispose()
                    }

                    { $_ -in 'HTTP', 'HTTPS' } {
                        Write-AdminLog -Message "Testing $testProtocol connection to $t" -Level Debug
                        
                        $webRequest = [System.Net.WebRequest]::Create($t)
                        $webRequest.Timeout = $Timeout * 1000
                        $webRequest.Method = 'HEAD'
                        
                        if ($Credential) {
                            $webRequest.Credentials = $Credential.GetNetworkCredential()
                        }

                        try {
                            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                            $response = $webRequest.GetResponse()
                            $stopwatch.Stop()
                            
                            $result.Reachable = $true
                            $result.ResponseTime = $stopwatch.ElapsedMilliseconds
                            $response.Close()
                        }
                        catch [System.Net.WebException] {
                            # Some HTTP errors still indicate connectivity
                            if ($_.Exception.Response) {
                                $result.Reachable = $true
                                $statusCode = [int]$_.Exception.Response.StatusCode
                                $result.ErrorMessage = "HTTP $statusCode`: $($_.Exception.Response.StatusDescription)"
                            } else {
                                $result.Reachable = $false
                                $result.ErrorMessage = $_.Exception.Message
                            }
                        }
                    }
                }

                # Log result
                if ($result.Reachable) {
                    Write-AdminLog -Message "$hostname is reachable via $testProtocol" -Level Success
                } else {
                    Write-AdminLog -Message "$hostname is not reachable via $testProtocol" -Level Warning
                }

            }
            catch {
                $result.ErrorMessage = $_.Exception.Message
                Write-AdminLog -Message "Connectivity test failed for $hostname`: $_" -Level Error
            }

            $results += $result
        }
    }

    end {
        if ($Detailed) {
            return $results
        } else {
            # Return simple boolean - true if all targets are reachable
            return ($results | Where-Object { -not $_.Reachable }).Count -eq 0
        }
    }
}