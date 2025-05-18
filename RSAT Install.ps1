$installed = Get-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -Online | Select-Object -ExpandProperty State

if ($installed -eq "NotPresent") {
    Add-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -Online
}
