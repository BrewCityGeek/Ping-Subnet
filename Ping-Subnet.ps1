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

.NOTES
    Author: Andy Gossen
    Date: 2025-10-08
    Version: 5.1 and higher -stable
#>


param(
    [string]$Subnet = $null,              # Full subnet in CIDR (auto-detect if not provided)
    [int]$MaxConcurrentJobs = 10,         # Max parallel jobs
    [string]$OutputCsv = $null,           # Optional: path to export CSV
    [switch]$ShowOffline                  # Optional: include offline hosts if specified
)


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
    try {
        $ping = Test-Connection -ComputerName $TargetIP -Count 1 -Quiet -ErrorAction SilentlyContinue
        $hostname = $null
        $mac = $null
        if ($ping) {
            $hostname = Get-Hostname $TargetIP
            $mac = Get-MacAddress $TargetIP
        }
        [PSCustomObject]@{
            IPAddress = $TargetIP
            Status    = if ($ping) { "Up" } else { "Down" }
            Hostname  = $hostname
            MAC       = $mac
        }
    } catch {
        [PSCustomObject]@{
            IPAddress = $TargetIP
            Status    = "Error: $_"
            Hostname  = $null
            MAC       = $null
        }
    }
}

# --- Main Script ---

Write-Host "Starting throttled scan of subnet $Subnet..." -ForegroundColor Yellow
$results = @() # Array to store results
$IPAddresses = Get-SubnetRange $Subnet
$total = $IPAddresses.Count
$counter = 0

# Loop through each IP address to create and manage the jobs.
foreach ($IP in $IPAddresses) {
    Start-Job -ScriptBlock $ScriptBlock -ArgumentList $IP | Out-Null
    $counter++
    Write-Progress -Activity "Pinging subnet..." -Status "Processing $counter of $total" -PercentComplete (($counter / $total) * 100)
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
$displayResults | Select-Object IPAddress, Status, Hostname, MAC | Format-Table -AutoSize

# Optionally export to CSV (respecting ShowOffline)
if ($OutputCsv) {
    $displayResults | Export-Csv -Path $OutputCsv -NoTypeInformation
    Write-Host "Results exported to $OutputCsv" -ForegroundColor Green
}
