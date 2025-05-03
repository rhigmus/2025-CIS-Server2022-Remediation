function Invoke-Control11198 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 11198: Status of the Allow Windows Ink Workspace setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 11198"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 11198: Status of the Allow Windows Ink Workspace setting"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0 -Type DWord
            $cmdOutput = "Disabled Windows Ink Workspace"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 11198: $_"
}
