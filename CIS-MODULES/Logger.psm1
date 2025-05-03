# Logger.psm1
# Provides centralized logging for CIS control modules

# Generate log file name using date + random suffix
$script:LogPath = "$PSScriptRoot\20250503_CIS-Remediation-Log_81FIGWyM.log"

function Set-LogPath {
    param([string]$path)
    $script:LogPath = $path
}

function Get-LogPath {
    return $script:LogPath
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp`t$Message"
    Add-Content -Path $script:LogPath -Value $entry
}
