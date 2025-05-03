# Logger.psm1

$script:LogPath = "$PSScriptRoot\$(Get-Date -Format 'yyyyMMdd')_CIS-Remediation-Log_{0}.log" -f (
    -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
)

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
