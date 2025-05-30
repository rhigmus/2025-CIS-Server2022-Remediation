function Invoke-Control4140 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 4140: Status of the Do not delete temp folder upon exit setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 4140"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 4140"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DeleteTempDirsOnExit" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Configured system to retain temp folders on exit."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 4140: $_"
}
}
