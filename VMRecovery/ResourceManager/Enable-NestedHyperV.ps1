try {
    $result = install-windowsfeature -name Hyper-V -IncludeManagementTools -ErrorAction Stop
}
catch {
    throw $_
    exit 1
}

if ($result.ExitCode -eq 'NoChangeNeeded')
{
    try {
        $switch = New-VMSwitch -Name Internal -SwitchType Internal -ErrorAction Stop
        $adapter = Get-NetAdapter -Name 'vEthernet (Internal)' -ErrorAction Stop
        $ip = New-NetIPAddress -IPAddress 192.168.0.1 -PrefixLength 24 -InterfaceIndex $adapter.ifIndex -ErrorAction Stop
        $nat = New-NetNat -Name InternalNAT -InternalIPInterfaceAddressPrefix 192.168.0.0/24 -ErrorAction Stop
        $dhcp = Install-WindowsFeature -Name DHCP -IncludeManagementTools -ErrorAction Stop
        $scope = Add-DhcpServerV4Scope -Name Scope1 -StartRange 192.168.0.100 -EndRange 192.168.0.200 -SubnetMask 255.255.255.0 -ErrorAction Stop
        $option = Set-DhcpServerV4OptionValue -Router 192.168.0.1 -ErrorAction Stop
        $newvm = new-vm -name ProblemVM -MemoryStartupBytes 4GB -NoVHD -BootDevice IDE -SwitchName Internal -Generation 1 -ErrorAction Stop
        $setvm = set-vm -name ProblemVM -ProcessorCount 2 -CheckpointType Disabled -ErrorAction Stop
        $disk = get-disk -ErrorAction Stop | where {$_.FriendlyName -eq 'Msft Virtual Disk'}
        set-disk -InputObject $disk -IsOffline $true -ErrorAction Stop
        $disk | Add-VMHardDiskDrive -VMName ProblemVM -ErrorAction Stop
        $startvm = start-vm -Name ProblemVM -ErrorAction Stop
        $getvm = get-vm -Name ProblemVM -ErrorAction Stop | select *
    }
    catch {
        throw $_
        exit 1
    }

    write-host $getvm
}
else
{
    write-host $result.ExitCode
    exit
}
