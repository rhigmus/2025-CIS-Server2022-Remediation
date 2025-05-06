function Invoke-Control8367 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8367: Status of the name of the Built-in Administrator account"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8367"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8367: Rename built-in Administrator account"
        try {
            Rename-LocalUser -Name "Administrator" -NewName "spgadmin"
            $cmdOutput = "Renamed built-in Administrator account 'spgadmin' "
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8367: $_"
}
}
