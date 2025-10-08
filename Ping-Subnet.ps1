<#
.SYNOPSIS
    Pings a subnet in parallel on PowerShell 5.1 using throttled background jobs.

.DESCRIPTION
    This script is designed for PowerShell environments (v5.1 and higher). It starts a 
    separate background job for each IP address ping but limits how many can run
    simultaneously to ensure stability.

.PARAMETERS
    -Subnet: The full subnet in CIDR notation (e.g.,
    -MaxConcurrentJobs: Maximum number of parallel jobs to run at once (default: 10).
    -OutputCsv: Optional path to export results as a CSV file.
    -ShowOffline: Switch to include offline hosts in the output (by default, only online hosts are shown).
    -Port: Optional TCP port to check on each host (default: 0, which skips port checking).
    -ErrorLog: Optional path to export errors to a CSV file.
    -Include: Optional list of specific IPs to include in the scan.
    -Exclude: Optional list of specific IPs to exclude from the scan.

.NOTES
    Author: Andy Gossen
    Date: 2025-10-08
    Version: 5.1 and higher -stable
#>


param(
    [string]$Subnet = $null,              # Full subnet in CIDR (auto-detect if not provided)
    [int]$MaxConcurrentJobs = 10,         # Max parallel jobs
    [string]$OutputCsv = $null,           # Optional: path to export CSV
    [switch]$ShowOffline,                 # Optional: include offline hosts if specified
    [int]$Port = 0,                       # Optional: TCP port to check (0 = skip)
    [string]$ErrorLog = $null,            # Optional: path to error log file
    [string[]]$Include = $null,           # Optional: list of IPs to include
    [string[]]$Exclude = $null            # Optional: list of IPs to exclude
)


# --- Input Validation ---
if ($MaxConcurrentJobs -lt 1 -or $MaxConcurrentJobs -gt 500) {
    Write-Host "WARNING: MaxConcurrentJobs should be between 1 and 500. Defaulting to 10." -ForegroundColor Yellow
    $MaxConcurrentJobs = 10
}
if ($MaxConcurrentJobs -gt 100) {
    Write-Host "WARNING: High parallelism may impact system performance!" -ForegroundColor Red
}

# --- Auto-detect Subnet (CIDR) if not provided ---
if (-not $Subnet) {
    $localNet = Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp | Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1
    if (-not $localNet) {
        $localNet = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1
    }
    if ($localNet) {
        $Subnet = "$($localNet.IPAddress)/$($localNet.PrefixLength)"
        Write-Host "Auto-detected subnet: $Subnet (from local IP $($localNet.IPAddress))" -ForegroundColor Cyan
    } else {
        Write-Host "ERROR: Could not auto-detect a valid local IPv4 address. Please specify -Subnet manually (e.g., 192.168.1.0/24)." -ForegroundColor Red
        exit 1
    }
}

# --- Calculate IP range from subnet ---
function Get-SubnetRange {
    param(
        [string]$SubnetCidr
    )
    $parts = $SubnetCidr -split '/'
    $ip = $parts[0]
    $prefix = [int]$parts[1]
    $ipBytes = $ip -split '\.' | ForEach-Object { [int]$_ }
    $ipInt = ($ipBytes[0] -shl 24) -bor ($ipBytes[1] -shl 16) -bor ($ipBytes[2] -shl 8) -bor $ipBytes[3]
    $mask = [uint32]([math]::Pow(2,32) - [math]::Pow(2,32-$prefix))
    $network = $ipInt -band $mask
    $broadcast = $network + ([math]::Pow(2,32-$prefix) - 1)
    $start = $network + 1
    $end = $broadcast - 1
    $ips = @()
    for ($i = $start; $i -le $end; $i++) {
        $octet1 = ($i -shr 24) -band 0xFF
        $octet2 = ($i -shr 16) -band 0xFF
        $octet3 = ($i -shr 8) -band 0xFF
        $octet4 = $i -band 0xFF
        $ips += "$octet1.$octet2.$octet3.$octet4"
    }
    return $ips
}


# --- Script Block ---
# This is the block of code that each background job will run.
$ScriptBlock = {
    param($TargetIP)
    function Get-Hostname {
        param($ip)
        try {
            $entry = [System.Net.Dns]::GetHostEntry($ip)
            return $entry.HostName
        } catch {
            return $null
        }
    }
    function Get-MacAddress {
        param($ip)
        $mac = $null
        try {
            $arp = arp -a $ip 2>$null | Select-String "\b$ip\b"
            if ($arp) {
                $parts = $arp -split '\s+'
                foreach ($part in $parts) {
                    if ($part -match '([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}') {
                        $mac = $part
                        break
                    }
                }
            }
        } catch {}
        return $mac
    }
    function Test-Port {
        param($ip, $port)
        if ($port -le 0) { return $null }
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect($ip, $port, $null, $null)
            $success = $iar.AsyncWaitHandle.WaitOne(1000, $false)
            if ($success -and $tcp.Connected) {
                $tcp.Close()
                return $true
            } else {
                $tcp.Close()
                return $false
            }
        } catch { return $false }
    }
    try {
        $ping = Test-Connection -ComputerName $TargetIP -Count 1 -Quiet -ErrorAction SilentlyContinue
        $hostname = $null
        $mac = $null
        $portOpen = $null
        if ($ping) {
            $hostname = Get-Hostname $TargetIP
            $mac = Get-MacAddress $TargetIP
            if ($using:Port -gt 0) {
                $portOpen = Test-Port $TargetIP $using:Port
            }
        }
        [PSCustomObject]@{
            IPAddress = $TargetIP
            Status    = if ($ping) { "Up" } else { "Down" }
            Hostname  = $hostname
            MAC       = $mac
            PortOpen  = $portOpen
        }
    } catch {
        [PSCustomObject]@{
            IPAddress = $TargetIP
            Status    = "Error: $_"
            Hostname  = $null
            MAC       = $null
            PortOpen  = $null
        }
    }
}

# --- Main Script ---

Write-Host "Starting throttled scan of subnet $Subnet..." -ForegroundColor Yellow
$results = @() # Array to store results

$IPAddresses = Get-SubnetRange $Subnet
# Apply include/exclude filters
if ($Include) {
    $IPAddresses = $IPAddresses | Where-Object { $Include -contains $_ }
}
if ($Exclude) {
    $IPAddresses = $IPAddresses | Where-Object { $Exclude -notcontains $_ }
}
$total = $IPAddresses.Count
$counter = 0

# Enhanced progress bar and timing
$startTime = Get-Date
# Loop through each IP address to create and manage the jobs.
foreach ($IP in $IPAddresses) {
    Start-Job -ScriptBlock $ScriptBlock -ArgumentList $IP | Out-Null
    $counter++
    $percent = [math]::Round(($counter / $total) * 100, 1)
    Write-Progress -Activity "Pinging subnet..." -Status "Processed $counter of $total ($percent%)" -PercentComplete $percent
    $runningJobs = Get-Job -State Running
    if ($runningJobs.Count -ge $MaxConcurrentJobs) {
        $finishedJob = $runningJobs | Wait-Job -Any
        $results += $finishedJob | Receive-Job -ErrorAction SilentlyContinue
        Remove-Job -Job $finishedJob -Force -ErrorAction SilentlyContinue
    }
}

# After the loop, wait for all remaining jobs to finish and collect their results.
Write-Host "Waiting for the final batch of jobs to complete..." -ForegroundColor Cyan
$remainingJobs = Get-Job
if ($remainingJobs) {
    $results += $remainingJobs | Wait-Job | Receive-Job -ErrorAction SilentlyContinue
    $remainingJobs | Remove-Job -Force -ErrorAction SilentlyContinue
}

# Final cleanup of any jobs that might have failed or been stopped.
Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue

# Sort and display results
$sortedResults = $results | Sort-Object { [version]$_.IPAddress }
Clear-Host
Write-Host "Scan complete. Results:" -ForegroundColor Yellow

# By default, hide offline hosts unless -ShowOffline is specified
if ($ShowOffline) {
    $displayResults = $sortedResults
} else {
    $displayResults = $sortedResults | Where-Object { $_.Status -eq 'Up' }
}
# Show PortOpen column if port check is enabled
if ($Port -gt 0) {
    $displayResults | Select-Object IPAddress, Status, Hostname, MAC, PortOpen | Format-Table -AutoSize
} else {
    $displayResults | Select-Object IPAddress, Status, Hostname, MAC | Format-Table -AutoSize
}

# Optionally export to CSV (respecting ShowOffline)
if ($OutputCsv) {
    $displayResults | Export-Csv -Path $OutputCsv -NoTypeInformation
    Write-Host "Results exported to $OutputCsv" -ForegroundColor Green
}

# Error logging
if ($ErrorLog) {
    $errorResults = $sortedResults | Where-Object { $_.Status -ne 'Up' }
    $errorResults | Export-Csv -Path $ErrorLog -NoTypeInformation
    Write-Host "Errors exported to $ErrorLog" -ForegroundColor Red
}

# Summary statistics
$up = ($sortedResults | Where-Object { $_.Status -eq 'Up' }).Count
$down = ($sortedResults | Where-Object { $_.Status -eq 'Down' }).Count
$err = ($sortedResults | Where-Object { $_.Status -like 'Error*' }).Count
$elapsed = (Get-Date) - $startTime
Write-Host ("`nSummary: Scanned $total hosts. Up: $up, Down: $down, Errors: $err. Time: {0:N1} sec" -f $elapsed.TotalSeconds) -ForegroundColor Cyan
