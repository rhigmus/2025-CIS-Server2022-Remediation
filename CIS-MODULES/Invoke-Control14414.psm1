function Invoke-Control14414 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 14414: Status of the Enumeration policy for external devices incompatible with Kernel DMA Protection setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 14414"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 14414"
        try {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection" -Name "DeviceEnumerationPolicy" -Value 0 -Type DWord
            $cmdOutput = "Set DeviceEnumerationPolicy to 0 (block incompatible devices)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 14414: $_"
}
