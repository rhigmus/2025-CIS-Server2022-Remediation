function Invoke-Control18122 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.1.2.2: Allow users to enable online speech recognition services"

    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
    $valueName = "AllowInputPersonalization"
    $desiredValue = 0

    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.1.2.2"
            return
        }
    }

    try {
        if (-not (Test-Path $registryPath)) {
            Write-Log "Registry path '$registryPath' does not exist. Creating it now."
            New-Item -Path $registryPath -Force | Out-Null
        }

        $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valueName -ErrorAction SilentlyContinue

        if ($currentValue -ne $desiredValue) {
            Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue -Type DWord
            Write-Log "Remediated: Set '$valueName' to '$desiredValue' under '$registryPath'"
        } else {
            Write-Log "No action needed: '$valueName' is already set to '$desiredValue' under '$registryPath'"
        }
    } catch {
        Write-Log "ERROR: Failed to apply remediation for Control ID 18.1.2.2 - $_"
    }
}