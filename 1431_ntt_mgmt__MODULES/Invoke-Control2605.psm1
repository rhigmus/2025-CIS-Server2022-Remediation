function Invoke-Control2605 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2605: Status of the User Account Control: Behavior of the elevation prompt for standard users setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2605"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2605: UAC elevation prompt behavior for standard users"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Set ConsentPromptBehaviorUser to 0 (automatically deny elevation requests for standard users)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2605: $_"
}
