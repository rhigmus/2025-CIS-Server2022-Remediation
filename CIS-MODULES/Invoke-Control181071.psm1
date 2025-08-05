function Invoke-Control181071 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.7.1: Status of the Disallow Autoplay for non-volume devices setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.7.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.7.1: Status of the Disallow Autoplay for non-volume devices setting"
        try {
            # Disallow Autoplay for non-volume devices
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoplayfornonVolume" -PropertyType DWord -Value 1 -Force | Out-Null
    
            $cmdOutput = "Set NoAutoplayfornonVolume to 1 (Autoplay disabled for non-volume devices)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.7.1: $_"
}
}
