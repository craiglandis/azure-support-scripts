try {
    $result = install-windowsfeature -name Hyper-V -IncludeManagementTools -ErrorAction Stop
}
catch {
    throw $_
    exit 1
}

if ($result.ExitCode -eq 'NoChangeNeeded')
{
    $nestedGuestVmName = 'ProblemVM'
    try {
        $switch = get-vmswitch -Name Internal -SwitchType Internal -ErrorAction SilentlyContinue | select -first 1
        if (!$switch)
        {
            $switch = New-VMSwitch -Name Internal -SwitchType Internal -ErrorAction Stop
        }

        $adapter = Get-NetAdapter -Name 'vEthernet (Internal)' -ErrorAction Stop

        $ip = get-netipaddress -IPAddress 192.168.0.1 -ErrorAction SilentlyContinue | select -first 1
        if (!$ip)
        {
            $ip = New-NetIPAddress -IPAddress 192.168.0.1 -PrefixLength 24 -InterfaceIndex $adapter.ifIndex -ErrorAction Stop
        }

        $nat = Get-NetNat -Name InternalNAT -ErrorAction SilentlyContinue | select -first 1
        if (!$nat)
        {
            $nat = New-NetNat -Name InternalNAT -InternalIPInterfaceAddressPrefix 192.168.0.0/24 -ErrorAction Stop
        }

        $dhcp = Install-WindowsFeature -Name DHCP -IncludeManagementTools -ErrorAction Stop

        $scope = Get-DhcpServerv4Scope | where Name -eq Scope1 | select -first 1
        if (!$scope)
        {
            $scope = Add-DhcpServerV4Scope -Name Scope1 -StartRange 192.168.0.100 -EndRange 192.168.0.200 -SubnetMask 255.255.255.0 -ErrorAction Stop
        }
        $option = Set-DhcpServerV4OptionValue -Router 192.168.0.1 -ErrorAction Stop
        $newvm = new-vm -name $nestedGuestVmName -MemoryStartupBytes 4GB -NoVHD -BootDevice IDE -Generation 1 -ErrorAction Stop
        $setvm = set-vm -name $nestedGuestVmName -ProcessorCount 2 -CheckpointType Disabled -ErrorAction Stop
        $disk = get-disk -ErrorAction Stop | where {$_.FriendlyName -eq 'Msft Virtual Disk'}
        $disk | set-disk -IsOffline $true -ErrorAction Stop
        $disk | Add-VMHardDiskDrive -VMName $nestedGuestVmName -ErrorAction Stop
        $switch | Connect-VMNetworkAdapter -VMName $nestedGuestVmName
        $startvm = start-vm -Name $nestedGuestVmName -ErrorAction Stop
        $nestedGuestVmState = (get-vm -Name $nestedGuestVmName -ErrorAction Stop).State
    }
    catch {
        throw $_
        exit 1
    }

    $nestedGuestVmState
}
else
{
    write-host $result.ExitCode
    exit
}
