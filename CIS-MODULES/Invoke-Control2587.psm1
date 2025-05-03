function Invoke-Control2587 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2587: Status of the User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2587"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2587: UAC elevation prompt behavior for administrators"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -PropertyType DWord -Value 2 -Force | Out-Null
            $cmdOutput = "Set ConsentPromptBehaviorAdmin to 2 (prompt for credentials on the secure desktop)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2587: $_"
}
