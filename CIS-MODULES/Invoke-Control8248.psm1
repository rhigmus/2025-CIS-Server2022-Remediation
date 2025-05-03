function Invoke-Control8248 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8248: Status of the Disallow Digest authentication setting (WinRM client)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8248"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8248: Status of the Disallow Digest authentication setting (WinRM client)"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value 0 -Type DWord
            $cmdOutput = "Disabled Digest authentication for WinRM client"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8248: $_"
}
