function Invoke-Control2612 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2612: Status of the Turn off downloading of enclosures setting (Internet Explorer)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2612"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2612: Status of the Turn off downloading of enclosures setting (Internet Explorer)"
        try {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Value 1 -Type DWord
            $cmdOutput = "Disabled downloading of enclosures in Internet Explorer"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2612: $_"
}
}
