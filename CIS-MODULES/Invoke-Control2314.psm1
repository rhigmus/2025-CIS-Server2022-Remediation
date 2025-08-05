function Invoke-Control2314 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.1.4: Status of the name of the Built-in Administrator account"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.1.4"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.1.4: Rename built-in Administrator account"
        try {
            Rename-LocalUser -Name "Administrator" -NewName "spgadmin"
            $cmdOutput = "Renamed built-in Administrator account 'spgadmin' "
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.1.4: $_"
}
}
