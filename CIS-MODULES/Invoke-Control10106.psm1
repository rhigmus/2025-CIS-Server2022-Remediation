function Invoke-Control10106 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10106: Status of Toggle user control over Insider builds"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10106"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10106: Status of Toggle user control over Insider builds"
        try {
            # Disable user control over Insider builds
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -PropertyType DWord -Value 0 -Force | Out-Null
    
            $cmdOutput = "Disabled user control over receiving Insider builds (AllowBuildPreview set to 0)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10106: $_"
}
