function Invoke-Control18109241 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.92.4.1: Status of Manage preview builds: Set the behavior of receiving preview builds setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.92.4.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.92.4.1: Status of Manage preview builds: Set the behavior of receiving preview builds setting"
        try {
            # Block preview builds from being received or installed
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -PropertyType DWord -Value 0 -Force | Out-Null
    
            $cmdOutput = "Disabled receiving of preview builds (EnableConfigFlighting set to 0)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.92.4.1: $_"
}
}
