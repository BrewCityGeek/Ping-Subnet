# Subnet-Discovery
Pings a subnet in parallel on PowerShell 5.1 using throttled background jobs.

## DESCRIPTION
This script is designed for PowerShell environments (v5.1 and higher). It starts a separate background job for each IP address ping but limits how many can run simultaneously to ensure stability.


### PARAMETERS
    -Subnet: The full subnet in CIDR notation (e.g.,
    -MaxConcurrentJobs: Maximum number of parallel jobs to run at once (default: 10).
    -OutputCsv: Optional path to export results as a CSV file.
    -ShowOffline: Switch to include offline hosts in the output (by default, only online hosts are shown).
    -Port: Optional TCP port to check on each host (default: 0, which skips port checking).
    -ErrorLog: Optional path to export errors to a CSV file.
    -Include: Optional list of specific IPs to include in the scan.
    -Exclude: Optional list of specific IPs to exclude from the scan.
