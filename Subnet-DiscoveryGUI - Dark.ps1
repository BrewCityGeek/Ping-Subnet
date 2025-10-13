<#
.SYNOPSIS
    Pings a subnet in parallel on PowerShell 5.1 using throttled background jobs with GUI interface.

.DESCRIPTION
    This script provides a Windows Forms GUI for subnet discovery. It displays current network
    configuration, allows customization of scan parameters, and shows real-time progress.
    The GUI includes options for CSV export, port scanning, and live log display.

.PARAMETERS
    -GUI: Switch to launch the GUI interface (default behavior).
    -Subnet: The full subnet in CIDR notation (for command-line use).
    -MaxConcurrentJobs: Maximum number of parallel jobs to run at once (default: 10).
    -OutputCsv: Optional path to export results as a CSV file.
    -ShowOffline: Switch to include offline hosts in the output.
    -Port: Optional TCP port to check on each host (default: 0, which skips port checking).
    -ErrorLog: Optional path to export errors to a CSV file.
    -Include: Optional list of specific IPs to include in the scan.
    -Exclude: Optional list of specific IPs to exclude from the scan.

.NOTES
    Author: Andy Gossen
    Date: 2025-10-11
    Version: 5.1 and higher - GUI Edition
#>


param(
    [switch]$GUI = $true,                 # Launch GUI interface
    [string]$Subnet = $null,              # Full subnet in CIDR (auto-detect if not provided)
    [int]$MaxConcurrentJobs = 10,         # Max parallel jobs
    [string]$OutputCsv = $null,           # Optional: path to export CSV
    [switch]$ShowOffline,                 # Optional: include offline hosts if specified
    [int]$Port = 0,                       # Optional: TCP port to check (0 = skip)
    [string]$ErrorLog = $null,            # Optional: path to error log file
    [string[]]$Include = $null,           # Optional: list of IPs to include
    [string[]]$Exclude = $null            # Optional: list of IPs to exclude
)

# Load required assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# P/Invoke to disable visual themes for TabControl
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    public extern static int SetWindowTheme(IntPtr hWnd, string pszSubAppName, string pszSubIdList);
}
"@

# Global variables for GUI
$global:ScanResults = @()
$global:ScanJobs = @()
$global:ScanActive = $false
$global:ScanTimer = $null
$global:ScanIPAddresses = @()
$global:ScanCurrentIndex = 0
$global:ScanTotalIPs = 0
$global:ScanStartTime = $null
$global:ScanMaxJobs = 10
$global:ScanPortsToScan = @()
$global:ScanShowOffline = $false
$global:DarkMode = $true  # Default to dark mode


# --- Original Core Functions ---

# --- Input Validation ---

function Get-NetworkConfig {
    $localNet = Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp | Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1
    if (-not $localNet) {
        $localNet = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1
    }
    
    $networkInfo = @{
        IPAddress = if ($localNet) { $localNet.IPAddress } else { "N/A" }
        SubnetMask = if ($localNet) { $localNet.PrefixLength } else { "N/A" }
        Subnet = if ($localNet) { "$($localNet.IPAddress)/$($localNet.PrefixLength)" } else { "N/A" }
        Gateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1).NextHop
        DNS = (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses }).ServerAddresses -join ", "
    }
    return $networkInfo
}

function Set-Theme {
    param([bool]$DarkMode)
    
    if ($DarkMode) {
        # Dark Mode Colors
        $bgColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
        $fgColor = [System.Drawing.Color]::White
        $panelColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
        $textBoxBg = [System.Drawing.Color]::FromArgb(60, 60, 60)
        $textBoxFg = [System.Drawing.Color]::White
        $groupBoxFg = [System.Drawing.Color]::LightGray
        $labelFg = [System.Drawing.Color]::LightGray
        $gridBg = [System.Drawing.Color]::FromArgb(45, 45, 45)
        $gridFg = [System.Drawing.Color]::White
        $gridAltBg = [System.Drawing.Color]::FromArgb(55, 55, 55)
        $gridHeaderBg = [System.Drawing.Color]::FromArgb(70, 70, 70)
        $logBg = [System.Drawing.Color]::FromArgb(25, 25, 25)
        $themeButtonText = "Light Mode"
        $tabBgColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
        # Button colors for dark mode
        $startButtonBg = [System.Drawing.Color]::FromArgb(40, 120, 40)
        $startButtonFg = [System.Drawing.Color]::White
        $stopButtonBg = [System.Drawing.Color]::FromArgb(140, 40, 40)
        $stopButtonFg = [System.Drawing.Color]::White
        $exportButtonBg = [System.Drawing.Color]::FromArgb(40, 100, 140)
        $exportButtonFg = [System.Drawing.Color]::White
        $themeButtonBg = [System.Drawing.Color]::FromArgb(90, 90, 90)
        $themeButtonFg = [System.Drawing.Color]::White
    } else {
        # Light Mode Colors
        $bgColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
        $fgColor = [System.Drawing.Color]::Black
        $panelColor = [System.Drawing.Color]::White
        $textBoxBg = [System.Drawing.Color]::White
        $textBoxFg = [System.Drawing.Color]::Black
        $groupBoxFg = [System.Drawing.Color]::Black
        $labelFg = [System.Drawing.Color]::Black
        $gridBg = [System.Drawing.Color]::White
        $gridFg = [System.Drawing.Color]::Black
        $gridAltBg = [System.Drawing.Color]::FromArgb(245, 245, 245)
        $gridHeaderBg = [System.Drawing.Color]::FromArgb(230, 230, 230)
        $logBg = [System.Drawing.Color]::FromArgb(248, 248, 248)
        $themeButtonText = "Dark Mode"
        $tabBgColor = [System.Drawing.Color]::FromArgb(225, 225, 225)
        # Button colors for light mode
        $startButtonBg = [System.Drawing.Color]::LightGreen
        $startButtonFg = [System.Drawing.Color]::Black
        $stopButtonBg = [System.Drawing.Color]::LightCoral
        $stopButtonFg = [System.Drawing.Color]::Black
        $exportButtonBg = [System.Drawing.Color]::LightBlue
        $exportButtonFg = [System.Drawing.Color]::Black
        $themeButtonBg = [System.Drawing.Color]::FromArgb(200, 200, 200)
        $themeButtonFg = [System.Drawing.Color]::Black
    }
    
    # Apply to main form
    $form.BackColor = $bgColor
    $form.ForeColor = $fgColor
    $form.Text = 'Network Subnet Discovery - ' + $(if ($DarkMode) { 'Dark' } else { 'Light' }) + ' Theme'
    
    # Apply to tabs - simple FlatButtons approach
    $tabControl.BackColor = $bgColor
    $tabControl.ForeColor = $fgColor
    $configTab.BackColor = $bgColor
    $configTab.ForeColor = $fgColor
    $configTab.UseVisualStyleBackColor = $false
    $resultsTab.BackColor = $bgColor
    $resultsTab.ForeColor = $fgColor
    $resultsTab.UseVisualStyleBackColor = $false
    $logTab.BackColor = $bgColor
    $logTab.ForeColor = $fgColor
    $logTab.UseVisualStyleBackColor = $false
    
    # Apply to groups with enhanced styling
    $networkGroup.BackColor = $panelColor
    $networkGroup.ForeColor = $groupBoxFg
    $networkGroup.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $scanGroup.BackColor = $panelColor
    $scanGroup.ForeColor = $groupBoxFg
    $scanGroup.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    
    # Apply to labels
    $networkInfoLabel.BackColor = $panelColor
    $networkInfoLabel.ForeColor = $labelFg
    $subnetLabel.ForeColor = $labelFg
    $autoSubnetLabel.ForeColor = if ($DarkMode) { [System.Drawing.Color]::SkyBlue } else { [System.Drawing.Color]::Blue }
    $jobsLabel.ForeColor = $labelFg
    $portHelpLabel.ForeColor = if ($DarkMode) { [System.Drawing.Color]::DarkGray } else { [System.Drawing.Color]::Gray }
    $statusLabel.ForeColor = $labelFg
    $recentLogLabel.ForeColor = $labelFg
    
    # Apply to text boxes
    $subnetTextBox.BackColor = $textBoxBg
    $subnetTextBox.ForeColor = $textBoxFg
    $portTextBox.BackColor = $textBoxBg
    $portTextBox.ForeColor = $textBoxFg
    $recentLogTextBox.BackColor = $logBg
    $recentLogTextBox.ForeColor = $textBoxFg
    $logTextBox.BackColor = $logBg
    $logTextBox.ForeColor = $textBoxFg
    
    # Apply to numeric up/down
    $jobsNumeric.BackColor = $textBoxBg
    $jobsNumeric.ForeColor = $textBoxFg
    
    # Apply to checkboxes
    $portCheckBox.BackColor = $panelColor
    $portCheckBox.ForeColor = $labelFg
    $showOfflineCheckBox.BackColor = $panelColor
    $showOfflineCheckBox.ForeColor = $labelFg
    
    # Apply to buttons with proper contrast
    $startButton.BackColor = $startButtonBg
    $startButton.ForeColor = $startButtonFg
    $startButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $startButton.FlatAppearance.BorderColor = if ($DarkMode) { [System.Drawing.Color]::FromArgb(60, 180, 60) } else { [System.Drawing.Color]::Green }
    
    $stopButton.BackColor = $stopButtonBg
    $stopButton.ForeColor = $stopButtonFg
    $stopButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $stopButton.FlatAppearance.BorderColor = if ($DarkMode) { [System.Drawing.Color]::FromArgb(200, 60, 60) } else { [System.Drawing.Color]::Red }
    
    $exportButton.BackColor = $exportButtonBg
    $exportButton.ForeColor = $exportButtonFg
    $exportButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $exportButton.FlatAppearance.BorderColor = if ($DarkMode) { [System.Drawing.Color]::FromArgb(60, 140, 200) } else { [System.Drawing.Color]::Blue }
    
    $themeButton.BackColor = $themeButtonBg
    $themeButton.ForeColor = $themeButtonFg
    $themeButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $themeButton.FlatAppearance.BorderColor = if ($DarkMode) { [System.Drawing.Color]::FromArgb(130, 130, 130) } else { [System.Drawing.Color]::Gray }
    
    # Apply to progress bar with enhanced styling
    $progressBar.BackColor = $panelColor
    $progressBar.ForeColor = if ($DarkMode) { [System.Drawing.Color]::LimeGreen } else { [System.Drawing.Color]::Blue }
    
    # Apply to data grid
    $resultsGrid.BackgroundColor = $gridBg
    $resultsGrid.ForeColor = $gridFg
    $resultsGrid.DefaultCellStyle.BackColor = $gridBg
    $resultsGrid.DefaultCellStyle.ForeColor = $gridFg
    $resultsGrid.AlternatingRowsDefaultCellStyle.BackColor = $gridAltBg
    $resultsGrid.ColumnHeadersDefaultCellStyle.BackColor = $gridHeaderBg
    $resultsGrid.ColumnHeadersDefaultCellStyle.ForeColor = $gridFg
    $resultsGrid.EnableHeadersVisualStyles = $false
    $resultsGrid.GridColor = if ($DarkMode) { [System.Drawing.Color]::FromArgb(80, 80, 80) } else { [System.Drawing.Color]::FromArgb(200, 200, 200) }
    
    # Update theme button text
    $themeButton.Text = $themeButtonText
    
    # Store current theme
    $global:DarkMode = $DarkMode
    
    # Refresh the form
    $form.Refresh()
}

function Toggle-Theme {
    $global:DarkMode = -not $global:DarkMode
    Set-Theme $global:DarkMode
    Update-LogDisplay "Theme switched to $(if ($global:DarkMode) { 'Dark Mode' } else { 'Light Mode' })"
}

function Update-LogDisplay {
    param([string]$Message, [string]$Color = "Black")
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    
    # Update the full log tab
    $logTextBox.AppendText("$logMessage`r`n")
    $logTextBox.ScrollToCaret()
    
    # Update the recent log on main tab (keep last 12 entries)
    if ($recentLogTextBox) {
        $recentLogTextBox.AppendText("$logMessage`r`n")
        
        # Keep only the last 12 lines in the recent log
        $lines = $recentLogTextBox.Text -split "`r`n"
        if ($lines.Count -gt 12) {
            $recentLines = $lines | Select-Object -Last 12
            $recentLogTextBox.Text = $recentLines -join "`r`n"
        }
        $recentLogTextBox.ScrollToCaret()
    }
    
    $form.Refresh()
}

function Update-Results {
    param($Results)
    
    $dataTable = New-Object System.Data.DataTable
    $dataTable.Columns.Add("IP Address") | Out-Null
    $dataTable.Columns.Add("Status") | Out-Null
    $dataTable.Columns.Add("Hostname") | Out-Null
    $dataTable.Columns.Add("MAC Address") | Out-Null
    
    # Add port columns dynamically based on scanned ports
    $portsToShow = @()
    if ($portCheckBox.Checked -and $portTextBox.Text) {
        $portsToShow = Get-PortList $portTextBox.Text
        foreach ($port in $portsToShow) {
            $dataTable.Columns.Add("Port $port") | Out-Null
        }
    }
    
    $displayResults = if ($showOfflineCheckBox.Checked) { $Results } else { $Results | Where-Object { $_.Status -eq 'Up' } }
    foreach ($result in $displayResults) {
        $row = $dataTable.NewRow()
        $row["IP Address"] = $result.IPAddress
        $row["Status"] = $result.Status
        $row["Hostname"] = if ($result.Hostname) { $result.Hostname } else { "-" }
        $row["MAC Address"] = if ($result.MAC) { $result.MAC } else { "-" }
        
        # Add port scan results
        foreach ($port in $portsToShow) {
            if ($result.PortResults -and $result.PortResults.ContainsKey($port)) {
                $portStatus = $result.PortResults[$port]
                $row["Port $port"] = if ($portStatus -eq $true) { "Open" } elseif ($portStatus -eq $false) { "Closed" } else { "-" }
            } else {
                $row["Port $port"] = "-"
            }
        }
        
        $dataTable.Rows.Add($row)
    }
    
    $resultsGrid.DataSource = $dataTable
    $resultsGrid.Refresh()
}

function Start-NetworkScan {
    if ($global:ScanActive) {
        [System.Windows.Forms.MessageBox]::Show("Scan is already in progress!", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $global:ScanActive = $true
    $global:ScanResults = @()
    $resultsGrid.DataSource = $null
    $resultsGrid.Refresh()
    $logTextBox.Clear()
    
    # Disable start button, enable stop button
    $startButton.Enabled = $false
    $stopButton.Enabled = $true
    
    # Get parameters from GUI
    $targetSubnet = if ($subnetTextBox.Text) { 
        $subnetTextBox.Text 
    } else { 
        # Extract the actual subnet from the auto-detected label (remove "Auto: " prefix)
        $autoSubnetLabel.Text -replace '^Auto:\s*', ''
    }
    
    # Fix: Handle potential string values in NumericUpDown control
    try {
        if ($jobsNumeric.Value -is [string]) {
            # If the value is a string (like "Auto: 10"), extract the numeric part
            $numericPart = $jobsNumeric.Value -replace '.*:\s*(\d+).*', '$1'
            $maxJobs = [int]$numericPart
        } else {
            $maxJobs = [int]$jobsNumeric.Value
        }
    } catch {
        Update-LogDisplay "Warning: Invalid jobs value, using default of 10"
        $maxJobs = 10
    }
    
    $portsToScan = if ($portCheckBox.Checked) { Get-PortList $portTextBox.Text } else { @() }
    $showOfflineHosts = $showOfflineCheckBox.Checked
    
    # Determine ping method based on PowerShell version
    $psVersion = $PSVersionTable.PSVersion.Major
    $pingMethod = if ($psVersion -ge 6) { "PowerShell Test-Connection with 1s timeout" } else { "CMD ping with 1s timeout" }
    
    Update-LogDisplay "Starting scan of subnet: $targetSubnet"
    Update-LogDisplay "PowerShell version: $psVersion - Using: $pingMethod"
    Update-LogDisplay "Max concurrent jobs: $maxJobs"
    if ($portsToScan.Count -gt 0) {
        Update-LogDisplay "Port scanning enabled: $($portsToScan -join ', ')"
    }
    
    # Initialize scan variables
    try {
        $global:ScanIPAddresses = Get-SubnetRange $targetSubnet
        $global:ScanResults = @()
        $global:ScanCurrentIndex = 0
        $global:ScanTotalIPs = $global:ScanIPAddresses.Count
        $global:ScanStartTime = Get-Date
        $global:ScanMaxJobs = $maxJobs
        $global:ScanPortsToScan = $portsToScan
        $global:ScanShowOffline = $showOfflineHosts
        
        Update-LogDisplay "Scanning $($global:ScanTotalIPs) IP addresses..."
        $progressBar.Value = 0
        $statusLabel.Text = "Initializing scan..."
        
        # Create timer for managing the scan
        $global:ScanTimer = New-Object System.Windows.Forms.Timer
        $global:ScanTimer.Interval = 100  # Check every 100ms for responsiveness
        $global:ScanTimer.Add_Tick({
            try {
                # Start new jobs if we haven't processed all IPs and have capacity
                $runningJobs = Get-Job -State Running -ErrorAction SilentlyContinue
                $runningCount = if ($runningJobs) { $runningJobs.Count } else { 0 }
                
                while ($global:ScanCurrentIndex -lt $global:ScanTotalIPs -and $runningCount -lt $global:ScanMaxJobs) {
                    $ip = $global:ScanIPAddresses[$global:ScanCurrentIndex]
                    Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ip, $global:ScanPortsToScan | Out-Null
                    $global:ScanCurrentIndex++
                    $runningCount++
                }
                
                # Check for completed jobs
                $completedJobs = Get-Job -State Completed -ErrorAction SilentlyContinue
                if ($completedJobs) {
                    foreach ($job in $completedJobs) {
                        $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
                        if ($result) {
                            $global:ScanResults += $result
                            if ($result.Status -eq 'Up') {
                                Update-LogDisplay "Found active host: $($result.IPAddress) - $($result.Hostname)"
                            }
                        }
                        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                    }
                    
                    # Update results display
                    Update-Results ($global:ScanResults | Sort-Object { [version]$_.IPAddress })
                }
                
                # Update progress
                $processedIPs = $global:ScanCurrentIndex
                $completedJobs = $global:ScanResults.Count
                $percent = if ($global:ScanTotalIPs -gt 0) { 
                    [math]::Round(($completedJobs / $global:ScanTotalIPs) * 100, 1) 
                } else { 0 }
                
                $progressBar.Value = [math]::Min($percent, 100)
                $statusLabel.Text = "Processed: $completedJobs/$($global:ScanTotalIPs) ($percent%) - Active jobs: $runningCount"
                
                # Check if scan is complete
                $allJobsCreated = $global:ScanCurrentIndex -ge $global:ScanTotalIPs
                $noRunningJobs = $runningCount -eq 0
                
                if ($allJobsCreated -and $noRunningJobs) {
                    # Scan completed
                    $global:ScanTimer.Stop()
                    $global:ScanTimer.Dispose()
                    $global:ScanTimer = $null
                    
                    # Final cleanup of any remaining jobs
                    Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue
                    
                    # Final results
                    $sortedResults = $global:ScanResults | Sort-Object { [version]$_.IPAddress }
                    Update-Results $sortedResults
                    
                    $up = ($sortedResults | Where-Object { $_.Status -eq 'Up' }).Count
                    $down = ($sortedResults | Where-Object { $_.Status -eq 'Down' }).Count
                    $elapsed = (Get-Date) - $global:ScanStartTime
                    
                    Update-LogDisplay "Scan completed! Up: $up, Down: $down, Time: $([math]::Round($elapsed.TotalSeconds, 1))s"
                    $progressBar.Value = 100
                    $statusLabel.Text = "Scan completed (Up: $up, Down: $down)"
                    
                    # Switch to Results tab automatically
                    $tabControl.SelectedTab = $resultsTab
                    
                    # Re-enable controls
                    $global:ScanActive = $false
                    $startButton.Enabled = $true
                    $stopButton.Enabled = $false
                    
                    # Store final results
                    $global:ScanResults = $sortedResults
                }
                
            } catch {
                Update-LogDisplay "Error during scan: $($_.Exception.Message)"
                # Stop the timer on error
                if ($global:ScanTimer) {
                    $global:ScanTimer.Stop()
                    $global:ScanTimer.Dispose()
                    $global:ScanTimer = $null
                }
                $global:ScanActive = $false
                $startButton.Enabled = $true
                $stopButton.Enabled = $false
            }
        })
        
        # Start the timer
        $global:ScanTimer.Start()
        
    } catch {
        Update-LogDisplay "Failed to start scan: $($_.Exception.Message)"
        $global:ScanActive = $false
        $startButton.Enabled = $true
        $stopButton.Enabled = $false
    }
}

function Stop-NetworkScan {
    if (-not $global:ScanActive) { return }
    
    Update-LogDisplay "Stopping scan..."
    
    # Stop the timer
    if ($global:ScanTimer) {
        $global:ScanTimer.Stop()
        $global:ScanTimer.Dispose()
        $global:ScanTimer = $null
    }
    
    # Clean up background jobs
    Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue
    
    $global:ScanActive = $false
    $startButton.Enabled = $true
    $stopButton.Enabled = $false
    $statusLabel.Text = "Scan stopped"
}

function Export-Results {
    if ($global:ScanResults.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No results to export!", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    $saveDialog.DefaultExt = "csv"
    $saveDialog.FileName = "subnet_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $exportResults = if ($showOfflineCheckBox.Checked) { $global:ScanResults } else { $global:ScanResults | Where-Object { $_.Status -eq 'Up' } }
            $exportResults | Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Force
            Update-LogDisplay "Results exported to: $($saveDialog.FileName)"
            [System.Windows.Forms.MessageBox]::Show("Results exported successfully to:`n$($saveDialog.FileName)", "Export Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Export Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
}

# --- Original Core Functions ---
if ($MaxConcurrentJobs -lt 1 -or $MaxConcurrentJobs -gt 500) {
    Write-Host "WARNING: MaxConcurrentJobs should be between 1 and 500. Defaulting to 10." -ForegroundColor Yellow
    $MaxConcurrentJobs = 10
}
if ($MaxConcurrentJobs -gt 100) {
    Write-Host "WARNING: High parallelism may impact system performance!" -ForegroundColor Red
}

# --- Auto-detect Subnet (CIDR) if not provided ---
function Get-AutoDetectedSubnet {
    $localNet = Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp | Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1
    if (-not $localNet) {
        $localNet = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1
    }
    if ($localNet) {
        return "$($localNet.IPAddress)/$($localNet.PrefixLength)"
    }
    return $null
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

# --- Parse port specification function ---
function Get-PortList {
    param([string]$PortSpec)
    
    if ([string]::IsNullOrWhiteSpace($PortSpec)) {
        return @()
    }
    
    $ports = @()
    $segments = $PortSpec -split ',' | ForEach-Object { $_.Trim() }
    
    foreach ($segment in $segments) {
        if ($segment -match '^(\d+)-(\d+)$') {
            # Range format: 80-90
            $start = [int]$matches[1]
            $end = [int]$matches[2]
            if ($start -le $end -and $start -ge 1 -and $end -le 65535) {
                for ($p = $start; $p -le $end; $p++) {
                    $ports += $p
                }
            }
        } elseif ($segment -match '^\d+$') {
            # Single port: 80
            $port = [int]$segment
            if ($port -ge 1 -and $port -le 65535) {
                $ports += $port
            }
        }
    }
    
    return ($ports | Sort-Object -Unique)
}


# --- Script Block ---
# This is the block of code that each background job will run.
$ScriptBlock = {
    param($TargetIP, $PortsToScan = @())
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
    function Test-MultiPorts {
        param($ip, $ports)
        $results = @{}
        foreach ($port in $ports) {
            $results[$port] = Test-Port $ip $port
        }
        return $results
    }
    function Test-FastPing {
        param($ip)
        try {
            # Check PowerShell version for optimal ping method
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                # PowerShell 6+ supports TimeoutSeconds parameter
                $ping = Test-Connection -ComputerName $ip -Count 1 -TimeoutSeconds 1 -Quiet -ErrorAction SilentlyContinue
                return $ping
            } else {
                # PowerShell 5.1 and below - use cmd ping with timeout
                $pingResult = cmd /c "ping -n 1 -w 1000 $ip" 2>$null
                if ($pingResult -match "TTL=") {
                    return $true
                } else {
                    return $false
                }
            }
        } catch {
            return $false
        }
    }
    try {
        $ping = Test-FastPing $TargetIP
        $hostname = $null
        $mac = $null
        $portResults = @{}
        if ($ping) {
            $hostname = Get-Hostname $TargetIP
            $mac = Get-MacAddress $TargetIP
            if ($PortsToScan.Count -gt 0) {
                $portResults = Test-MultiPorts $TargetIP $PortsToScan
            }
        }
        [PSCustomObject]@{
            IPAddress = $TargetIP
            Status    = if ($ping) { "Up" } else { "Down" }
            Hostname  = $hostname
            MAC       = $mac
            PortResults = $portResults
        }
    } catch {
        [PSCustomObject]@{
            IPAddress = $TargetIP
            Status    = "Error: $_"
            Hostname  = $null
            MAC       = $null
            PortResults = @{}
        }
    }
}

# --- Main Script ---

# Check if GUI mode is requested (default)
if ($GUI) {
    # Create main form with standard border
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Network Subnet Discovery Tool v5.1'
    $form.Size = New-Object System.Drawing.Size(1000, 700)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'Sizable'
    $form.MinimizeBox = $true
    $form.MaximizeBox = $true
    $form.MinimumSize = New-Object System.Drawing.Size(900, 600)
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Regular)
    
    # Set initial dark theme colors on form
    $form.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
    
    # Get current network configuration
    $networkConfig = Get-NetworkConfig
    $autoDetectedSubnet = Get-AutoDetectedSubnet

    # TabControl with Visual Styles disabled for better theming
    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Size = New-Object System.Drawing.Size(980, 660)
    $tabControl.Location = New-Object System.Drawing.Point(10, 10)
    $tabControl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    
    # Disable visual themes using P/Invoke
    $tabControl.Add_HandleCreated({
        try {
            [Win32]::SetWindowTheme($tabControl.Handle, "", "")
        } catch {}
    })
    
    # Enable partial custom drawing for tabs only
    try {
        $setStyleMethod = $tabControl.GetType().GetMethod("SetStyle", [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance)
        # Only enable UserPaint for background, let DrawItem handle tab rendering
        $setStyleMethod.Invoke($tabControl, @([System.Windows.Forms.ControlStyles]::ResizeRedraw, $true))
    } catch {
        # Fallback if SetStyle fails
    }
    
    $tabControl.DrawMode = [System.Windows.Forms.TabDrawMode]::OwnerDrawFixed
    $tabControl.SizeMode = [System.Windows.Forms.TabSizeMode]::Fixed
    $tabControl.ItemSize = New-Object System.Drawing.Size(150, 30)
    $tabControl.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
    $tabControl.ForeColor = [System.Drawing.Color]::White
    
    # Add custom tab drawing event for theming
    $tabControl.Add_DrawItem({
        param($sender, $e)
        
        try {
            $tabPage = $sender.TabPages[$e.Index]
            $tabRect = $e.Bounds
            
            # Get theme colors
            $isSelected = ($e.Index -eq $sender.SelectedIndex)
            if ($global:DarkMode) {
                $tabBackColor = if ($isSelected) { 
                    [System.Drawing.Color]::FromArgb(70, 70, 70) 
                } else { 
                    [System.Drawing.Color]::FromArgb(50, 50, 50) 
                }
                $tabTextColor = [System.Drawing.Color]::White
                $borderColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
            } else {
                $tabBackColor = if ($isSelected) { 
                    [System.Drawing.Color]::White 
                } else { 
                    [System.Drawing.Color]::FromArgb(240, 240, 240) 
                }
                $tabTextColor = [System.Drawing.Color]::Black
                $borderColor = [System.Drawing.Color]::FromArgb(160, 160, 160)
            }
            
            # Fill tab background
            $brush = New-Object System.Drawing.SolidBrush($tabBackColor)
            $e.Graphics.FillRectangle($brush, $tabRect)
            
            # Draw tab border (top and sides only for selected tab)
            $pen = New-Object System.Drawing.Pen($borderColor)
            if ($isSelected) {
                # Selected tab: draw top, left, and right borders
                $e.Graphics.DrawLine($pen, $tabRect.Left, $tabRect.Top, $tabRect.Right - 1, $tabRect.Top)
                $e.Graphics.DrawLine($pen, $tabRect.Left, $tabRect.Top, $tabRect.Left, $tabRect.Bottom)
                $e.Graphics.DrawLine($pen, $tabRect.Right - 1, $tabRect.Top, $tabRect.Right - 1, $tabRect.Bottom)
            } else {
                # Non-selected tab: draw bottom border only
                $e.Graphics.DrawLine($pen, $tabRect.Left, $tabRect.Bottom - 1, $tabRect.Right - 1, $tabRect.Bottom - 1)
            }
            
            # Draw tab text
            $textBrush = New-Object System.Drawing.SolidBrush($tabTextColor)
            $stringFormat = New-Object System.Drawing.StringFormat
            $stringFormat.Alignment = [System.Drawing.StringAlignment]::Center
            $stringFormat.LineAlignment = [System.Drawing.StringAlignment]::Center
            
            # Calculate text position
            $textRect = [System.Drawing.RectangleF]::new($tabRect.X, $tabRect.Y, $tabRect.Width, $tabRect.Height)
            $e.Graphics.DrawString($tabPage.Text, $sender.Font, $textBrush, $textRect, $stringFormat)
            
            # Clean up resources
            $brush.Dispose()
            $pen.Dispose()
            $textBrush.Dispose()
            $stringFormat.Dispose()
        }
        catch {
            # Fallback: just fill with a solid color if drawing fails
            $fallbackBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::LightGray)
            $e.Graphics.FillRectangle($fallbackBrush, $e.Bounds)
            $fallbackBrush.Dispose()
        }
    })

    # Configuration Tab
    $configTab = New-Object System.Windows.Forms.TabPage
    $configTab.Text = '  Configuration  '
    $configTab.UseVisualStyleBackColor = $false
    $configTab.Padding = New-Object System.Windows.Forms.Padding(5)
    $tabControl.TabPages.Add($configTab)

    # Network Info Group with enhanced styling
    $networkGroup = New-Object System.Windows.Forms.GroupBox
    $networkGroup.Text = 'Current Network Configuration'
    $networkGroup.Size = New-Object System.Drawing.Size(350, 150)
    $networkGroup.Location = New-Object System.Drawing.Point(10, 10)
    $networkGroup.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $networkGroup.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $configTab.Controls.Add($networkGroup)

    $networkInfoLabel = New-Object System.Windows.Forms.Label
    $networkInfoLabel.Text = @"
IP Address: $($networkConfig.IPAddress)
Subnet Mask: /$($networkConfig.SubnetMask)
Default Gateway: $($networkConfig.Gateway)
DNS Servers: $($networkConfig.DNS)
Auto-detected Subnet: $autoDetectedSubnet
"@
    $networkInfoLabel.Size = New-Object System.Drawing.Size(320, 120)
    $networkInfoLabel.Location = New-Object System.Drawing.Point(10, 20)
    $networkInfoLabel.Font = New-Object System.Drawing.Font('Consolas', 9)
    $networkGroup.Controls.Add($networkInfoLabel)

    # Scan Settings Group with enhanced styling
    $scanGroup = New-Object System.Windows.Forms.GroupBox
    $scanGroup.Text = 'Scan Settings'
    $scanGroup.Size = New-Object System.Drawing.Size(550, 210)
    $scanGroup.Location = New-Object System.Drawing.Point(380, 10)
    $scanGroup.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $scanGroup.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $configTab.Controls.Add($scanGroup)

    # Subnet input
    $subnetLabel = New-Object System.Windows.Forms.Label
    $subnetLabel.Text = 'Subnet (CIDR):'
    $subnetLabel.Size = New-Object System.Drawing.Size(100, 20)
    $subnetLabel.Location = New-Object System.Drawing.Point(10, 25)
    $scanGroup.Controls.Add($subnetLabel)

    $subnetTextBox = New-Object System.Windows.Forms.TextBox
    $subnetTextBox.Size = New-Object System.Drawing.Size(200, 20)
    $subnetTextBox.Location = New-Object System.Drawing.Point(120, 25)
    $subnetTextBox.Text = $Subnet
    # Add Enter key support - try multiple methods for compatibility
    $subnetTextBox.Add_KeyPress({
        if ($_.KeyChar -eq 13) {  # Enter key ASCII code
            if (-not $global:ScanActive) {
                Start-NetworkScan
            }
            $_.Handled = $true
        }
    })
    $subnetTextBox.Add_KeyUp({
        if ($_.KeyCode -eq 'Return') {  # Alternative method
            if (-not $global:ScanActive) {
                Start-NetworkScan
            }
        }
    })
    $scanGroup.Controls.Add($subnetTextBox)

    $autoSubnetLabel = New-Object System.Windows.Forms.Label
    $autoSubnetLabel.Text = 'Auto: ' + $autoDetectedSubnet
    $autoSubnetLabel.Size = New-Object System.Drawing.Size(400, 20)
    $autoSubnetLabel.Location = New-Object System.Drawing.Point(330, 25)
    $autoSubnetLabel.ForeColor = [System.Drawing.Color]::Blue
    $scanGroup.Controls.Add($autoSubnetLabel)

    # Max jobs
    $jobsLabel = New-Object System.Windows.Forms.Label
    $jobsLabel.Text = "Max Concurrent Jobs:"
    $jobsLabel.Size = New-Object System.Drawing.Size(120, 20)
    $jobsLabel.Location = New-Object System.Drawing.Point(10, 55)
    $scanGroup.Controls.Add($jobsLabel)

    $jobsNumeric = New-Object System.Windows.Forms.NumericUpDown
    $jobsNumeric.Size = New-Object System.Drawing.Size(60, 20)
    $jobsNumeric.Location = New-Object System.Drawing.Point(140, 55)
    $jobsNumeric.Minimum = 1
    $jobsNumeric.Maximum = 100
    $jobsNumeric.Value = [int]$MaxConcurrentJobs
    $jobsNumeric.DecimalPlaces = 0
    $scanGroup.Controls.Add($jobsNumeric)

    # Port scanning
    $portCheckBox = New-Object System.Windows.Forms.CheckBox
    $portCheckBox.Text = "Enable Port Scanning:"
    $portCheckBox.Size = New-Object System.Drawing.Size(150, 20)
    $portCheckBox.Location = New-Object System.Drawing.Point(10, 85)
    $portCheckBox.Checked = ($Port -gt 0)
    $scanGroup.Controls.Add($portCheckBox)

    $portTextBox = New-Object System.Windows.Forms.TextBox
    $portTextBox.Size = New-Object System.Drawing.Size(200, 20)
    $portTextBox.Location = New-Object System.Drawing.Point(170, 85)
    $portTextBox.Text = if ($Port -gt 0) { $Port.ToString() } else { "80,443,22" }
    $portTextBox.Enabled = $portCheckBox.Checked
    $scanGroup.Controls.Add($portTextBox)

    $portHelpLabel = New-Object System.Windows.Forms.Label
    $portHelpLabel.Text = 'Examples: 80  |  80,443,22  |  80-90  |  80,443,8000-8010'
    $portHelpLabel.Size = New-Object System.Drawing.Size(520, 15)
    $portHelpLabel.Location = New-Object System.Drawing.Point(10, 110)
    $portHelpLabel.Font = New-Object System.Drawing.Font('Arial', 7)
    $portHelpLabel.ForeColor = [System.Drawing.Color]::Gray
    $scanGroup.Controls.Add($portHelpLabel)

    $portCheckBox.Add_CheckedChanged({
        $portTextBox.Enabled = $portCheckBox.Checked
    })

    # Show offline hosts
    $showOfflineCheckBox = New-Object System.Windows.Forms.CheckBox
    $showOfflineCheckBox.Text = "Show Offline Hosts"
    $showOfflineCheckBox.Size = New-Object System.Drawing.Size(150, 20)
    $showOfflineCheckBox.Location = New-Object System.Drawing.Point(10, 130)
    $showOfflineCheckBox.Checked = $ShowOffline
    $scanGroup.Controls.Add($showOfflineCheckBox)

    # Control buttons
    $startButton = New-Object System.Windows.Forms.Button
    $startButton.Text = "Start Scan"
    $startButton.Size = New-Object System.Drawing.Size(100, 30)
    $startButton.Location = New-Object System.Drawing.Point(10, 160)
    $startButton.BackColor = [System.Drawing.Color]::FromArgb(40, 120, 40)
    $startButton.ForeColor = [System.Drawing.Color]::White
    $startButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $startButton.Add_Click({ Start-NetworkScan })
    $scanGroup.Controls.Add($startButton)

    $stopButton = New-Object System.Windows.Forms.Button
    $stopButton.Text = "Stop Scan"
    $stopButton.Size = New-Object System.Drawing.Size(100, 30)
    $stopButton.Location = New-Object System.Drawing.Point(120, 160)
    $stopButton.BackColor = [System.Drawing.Color]::FromArgb(140, 40, 40)
    $stopButton.ForeColor = [System.Drawing.Color]::White
    $stopButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $stopButton.Enabled = $false
    $stopButton.Add_Click({ Stop-NetworkScan })
    $scanGroup.Controls.Add($stopButton)

    $exportButton = New-Object System.Windows.Forms.Button
    $exportButton.Text = "Export CSV"
    $exportButton.Size = New-Object System.Drawing.Size(100, 30)
    $exportButton.Location = New-Object System.Drawing.Point(230, 160)
    $exportButton.BackColor = [System.Drawing.Color]::FromArgb(40, 100, 140)
    $exportButton.ForeColor = [System.Drawing.Color]::White
    $exportButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $exportButton.Add_Click({ Export-Results })
    $scanGroup.Controls.Add($exportButton)

    # Theme toggle button
    $themeButton = New-Object System.Windows.Forms.Button
    $themeButton.Text = "Light Mode"
    $themeButton.Size = New-Object System.Drawing.Size(100, 30)
    $themeButton.Location = New-Object System.Drawing.Point(340, 160)
    $themeButton.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
    $themeButton.ForeColor = [System.Drawing.Color]::White
    $themeButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $themeButton.Add_Click({ Toggle-Theme })
    $scanGroup.Controls.Add($themeButton)

    # Progress bar with enhanced styling
    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Size = New-Object System.Drawing.Size(920, 25)
    $progressBar.Location = New-Object System.Drawing.Point(10, 220)
    $progressBar.Style = "Continuous"
    $progressBar.MarqueeAnimationSpeed = 30
    $configTab.Controls.Add($progressBar)

    # Status label
    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Text = "Ready to scan"
    $statusLabel.Size = New-Object System.Drawing.Size(920, 20)
    $statusLabel.Location = New-Object System.Drawing.Point(10, 250)
    $statusLabel.Font = New-Object System.Drawing.Font('Arial', 9, [System.Drawing.FontStyle]::Bold)
    $configTab.Controls.Add($statusLabel)

    # Recent log display
    $recentLogLabel = New-Object System.Windows.Forms.Label
    $recentLogLabel.Text = "Recent Activity:"
    $recentLogLabel.Size = New-Object System.Drawing.Size(920, 20)
    $recentLogLabel.Location = New-Object System.Drawing.Point(10, 280)
    $recentLogLabel.Font = New-Object System.Drawing.Font('Arial', 9, [System.Drawing.FontStyle]::Bold)
    $configTab.Controls.Add($recentLogLabel)

    $recentLogTextBox = New-Object System.Windows.Forms.TextBox
    $recentLogTextBox.Size = New-Object System.Drawing.Size(920, 300)
    $recentLogTextBox.Location = New-Object System.Drawing.Point(10, 305)
    $recentLogTextBox.Multiline = $true
    $recentLogTextBox.ScrollBars = "Vertical"
    $recentLogTextBox.ReadOnly = $true
    $recentLogTextBox.Font = New-Object System.Drawing.Font('Consolas', 8)
    $recentLogTextBox.BackColor = [System.Drawing.Color]::FromArgb(248, 248, 248)
    $configTab.Controls.Add($recentLogTextBox)

    # Results Tab
    $resultsTab = New-Object System.Windows.Forms.TabPage
    $resultsTab.Text = "    Results    "
    $resultsTab.UseVisualStyleBackColor = $false
    $resultsTab.Padding = New-Object System.Windows.Forms.Padding(5)
    $tabControl.TabPages.Add($resultsTab)

    # Results grid
    $resultsGrid = New-Object System.Windows.Forms.DataGridView
    $resultsGrid.Size = New-Object System.Drawing.Size(920, 580)
    $resultsGrid.Location = New-Object System.Drawing.Point(10, 10)
    $resultsGrid.ReadOnly = $true
    $resultsGrid.AllowUserToAddRows = $false
    $resultsGrid.AllowUserToDeleteRows = $false
    $resultsGrid.SelectionMode = "FullRowSelect"
    $resultsGrid.AutoSizeColumnsMode = "AllCells"
    $resultsTab.Controls.Add($resultsGrid)

    # Log Tab
    $logTab = New-Object System.Windows.Forms.TabPage
    $logTab.Text = "      Log      "
    $logTab.UseVisualStyleBackColor = $false
    $logTab.Padding = New-Object System.Windows.Forms.Padding(5)
    $tabControl.TabPages.Add($logTab)

    # Log text box
    $logTextBox = New-Object System.Windows.Forms.TextBox
    $logTextBox.Size = New-Object System.Drawing.Size(950, 600)
    $logTextBox.Location = New-Object System.Drawing.Point(10, 10)
    $logTextBox.Multiline = $true
    $logTextBox.ScrollBars = "Vertical"
    $logTextBox.ReadOnly = $true
    $logTextBox.Font = New-Object System.Drawing.Font('Consolas', 9)
    $logTab.Controls.Add($logTextBox)

    # Add tab control to form
    # Create container panel with themed background
    $tabContainerPanel = New-Object System.Windows.Forms.Panel
    $tabContainerPanel.Size = $tabControl.Size
    $tabContainerPanel.Location = $tabControl.Location
    $tabContainerPanel.Anchor = $tabControl.Anchor
    $tabContainerPanel.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
    
    # Make TabControl fill the container
    $tabControl.Dock = [System.Windows.Forms.DockStyle]::Fill
    $tabControl.Location = New-Object System.Drawing.Point(0, 0)
    
    # Add TabControl to container
    $tabContainerPanel.Controls.Add($tabControl)
    $form.Controls.Add($tabContainerPanel)

    # Add form closing event handler for proper cleanup
    $form.Add_FormClosing({
        if ($global:ScanActive) {
            Stop-NetworkScan
        }
        # Ensure all resources are cleaned up
        if ($global:ScanTimer) {
            $global:ScanTimer.Stop()
            $global:ScanTimer.Dispose()
        }
        Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue
    })

    # Show form
    Update-LogDisplay "Network Discovery Tool initialized"
    Update-LogDisplay "Auto-detected subnet: $autoDetectedSubnet"
    
    # Apply initial theme (Dark Mode by default)
    Set-Theme $global:DarkMode
    
    # Enable key events for the form
    $form.KeyPreview = $true
    
    # Add Enter key handler to start scan
    $form.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            # Only start scan if not already active and start button is enabled
            if (-not $global:ScanActive -and $startButton.Enabled) {
                Start-NetworkScan
            }
        }
    })
    
    $form.ShowDialog()
    
} else {
    # Command-line mode (original functionality)
    # --- Auto-detect Subnet (CIDR) if not provided ---
    if (-not $Subnet) {
        $autoSubnet = Get-AutoDetectedSubnet
        if ($autoSubnet) {
            $Subnet = $autoSubnet
            Write-Host "Auto-detected subnet: $Subnet" -ForegroundColor Cyan
        } else {
            Write-Host "ERROR: Could not auto-detect a valid local IPv4 address. Please specify -Subnet manually (e.g., 192.168.1.0/24)." -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "Starting throttled scan of subnet $Subnet..." -ForegroundColor Yellow
    
    # Display ping method being used
    $psVersion = $PSVersionTable.PSVersion.Major
    $pingMethod = if ($psVersion -ge 6) { "PowerShell Test-Connection with 1s timeout" } else { "CMD ping with 1s timeout" }
    Write-Host "PowerShell version: $psVersion - Using: $pingMethod" -ForegroundColor Cyan

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
    # Convert single port to array for compatibility with new ScriptBlock
    $portsArray = if ($Port -gt 0) { @($Port) } else { @() }
    # Loop through each IP address to create and manage the jobs.
    foreach ($IP in $IPAddresses) {
        Start-Job -ScriptBlock $ScriptBlock -ArgumentList $IP, $portsArray | Out-Null
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
    # Show port results if port check is enabled
    if ($Port -gt 0) {
        # Add a calculated property to show the single port result for backward compatibility
        $displayResults = $displayResults | Select-Object IPAddress, Status, Hostname, MAC, @{
            Name = "Port$Port"
            Expression = { 
                if ($_.PortResults -and $_.PortResults.ContainsKey($Port)) {
                    if ($_.PortResults[$Port] -eq $true) { "Open" } 
                    elseif ($_.PortResults[$Port] -eq $false) { "Closed" } 
                    else { "-" }
                } else { "-" }
            }
        }
        $displayResults | Format-Table -AutoSize
    } else {
        $displayResults | Select-Object IPAddress, Status, Hostname, MAC | Format-Table -AutoSize
    }

    # Optionally export to CSV (respecting ShowOffline)
    if ($OutputCsv) {
        $displayResults | Export-Csv -Path $OutputCsv -NoTypeInformation -Force
        Write-Host "Results exported to $OutputCsv" -ForegroundColor Green
    }

    # Error logging (exports only entries where Status starts with 'Error')
    if ($ErrorLog) {
        $errorResults = $sortedResults | Where-Object { $_.Status -like 'Error*' }
        $errorResults | Export-Csv -Path $ErrorLog -NoTypeInformation
        Write-Host "Errors exported to $ErrorLog" -ForegroundColor Red
    }

    # Summary statistics
    $up = ($sortedResults | Where-Object { $_.Status -eq 'Up' }).Count
    $down = ($sortedResults | Where-Object { $_.Status -eq 'Down' }).Count
    $err = ($sortedResults | Where-Object { $_.Status -like 'Error*' }).Count
    $elapsed = (Get-Date) - $startTime
    Write-Host ("`nSummary: Scanned $total hosts. Up: $up, Down: $down, Errors: $err. Time elapsed: {0:N1} seconds" -f $elapsed.TotalSeconds) -ForegroundColor Cyan
}