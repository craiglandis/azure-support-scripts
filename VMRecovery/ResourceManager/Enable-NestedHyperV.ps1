$nestedGuestVmName = 'ProblemVM'
$batchFile = "$env:allusersprofile\Microsoft\Windows\Start Menu\Programs\StartUp\RunHyperVManagerAndVMConnect.cmd"
$batchFileContents = @"
start $env:windir\System32\mmc.exe $env:windir\System32\virtmgmt.msc
start $env:windir\System32\vmconnect.exe localhost $nestedGuestVmName
"@

$features = get-windowsfeature
$hyperv = $features | where Name -eq 'Hyper-V'
$hypervTools = $features | where Name -eq 'Hyper-V-Tools'
$hypervPowerShell = $features | where Name -eq 'Hyper-V-Powershell'

if ($hyperv.Installed -and $hypervTools.Installed -and $hypervPowerShell.Installed)
{
    # Sets "Do not start Server Manager automatically at logon"
    $return = New-ItemProperty -Path HKLM:\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value 1 -force -ErrorAction SilentlyContinue
    $return = New-ItemProperty -Path HKLM:\Software\Microsoft\ServerManager\Oobe -Name DoNotOpenInitialConfigurationTasksAtLogon -PropertyType DWORD -Value 1 -force -ErrorAction SilentlyContinue

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
        $batchFileContents | out-file -FilePath $batchFile -Force -Encoding Default
        $return = copy-item -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Hyper-V Manager.lnk" -Destination "C:\Users\Public\Desktop"
        $return = new-item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" -Force
    }
    catch {
        throw $_
        exit 1
    }

    $nestedGuestVmState
}
else
{
    try {
        $result = install-windowsfeature -name Hyper-V -IncludeManagementTools -ErrorAction Stop
    }
    catch {
        throw $_
        exit 1
    }
    write-host $result.ExitCode
}