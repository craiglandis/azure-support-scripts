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
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    $numPixels = 100
    $bmpFile = new-object System.Drawing.Bitmap($numPixels,$numPixels)
    $image = [System.Drawing.Graphics]::FromImage($bmpFile)
    $rectangle = new-object Drawing.Rectangle 0, 0, $numPixels, $numPixels
    $image.DrawImage($bmpFile, $rectangle, 0, 0, $numPixels, $numPixels, ([Drawing.GraphicsUnit]::Pixel))

    $wallpaperFolderPath = "$env:windir\WEB\wallpaper\Windows"
    $wallpaperFileName = "img0.jpg"
    $wallpaperFilePath = "$wallpaperFolderPath\$wallpaperFileName"
    $return = takeown /f $wallpaperFilePath
    $return = icacls $wallpaperFilePath /Grant System:F
    $return = icacls $wallpaperFilePath /grant Administrators:F
    if ((test-path -path "$wallpaperFolderPath\img0.jpg.bak") -eq $false)
    {
        copy-item -Path $wallpaperFilePath -Destination "$wallpaperFolderPath\img0.jpg.bak" -Force
    }
    remove-item -Path $wallpaperFilePath -Force
    $bmpFile.Save($wallpaperFilePath, [System.Drawing.Imaging.ImageFormat]::jpeg)
    $bmpFile.Dispose()

    $return = New-ItemProperty -Path HKLM:\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value 1 -force -ErrorAction SilentlyContinue
    $return = New-ItemProperty -Path HKLM:\Software\Microsoft\ServerManager\Oobe -Name DoNotOpenInitialConfigurationTasksAtLogon -PropertyType DWORD -Value 1 -force -ErrorAction SilentlyContinue
<#
    $builtinAdminProfilePath = (Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue | where {$_.SID.EndsWith('-500')} | select LocalPath).LocalPath
    $builtinAdminHivePath = "$builtinAdminProfilePath\NTUSER.DAT"
    if (test-path -Path $builtinAdminHivePath)
    {
        $builtinAdminHiveTempRegPath = "HKU\BuiltInAdmin"
        try {
            $return = reg load $builtinAdminHiveTempRegPath $builtinAdminHivePath
            $return = reg add "$builtinAdminHiveTempRegPath\Control Panel\Desktop" /v WallPaper /t REG_SZ /f
            WallpaperStyle
            $return = reg add "$builtinAdminHiveTempRegPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" /v BackgroundType /t REG_DWORD /d 1 /f
            $return = reg unload $builtinAdminHiveTempRegPath
        }
        catch {
            # Catching as non-fatal since setting wallpaper is not essential to the script's overall goal.
        }
    }

    $defaultUserHivePath = "$env:SystemDrive\Users\Default\NTUSER.DAT"

    if (test-path -Path $defaultUserHivePath)
    {
        $defaultUserHiveTempRegPath = "HKU\Default"
        try {
            $return = reg load $defaultUserHiveTempRegPath $defaultUserHivePath
            $return = reg add "$defaultUserHiveTempRegPath\Control Panel\Desktop" /v WallPaper /t REG_SZ /f
            $return = reg add "$defaultUserHiveTempRegPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" /v BackgroundType /t REG_DWORD /d 1 /f
            $return = reg unload $defaultUserHiveTempRegPath
        }
        catch {
            # Catching as non-fatal since setting wallpaper is not essential to the script's overall goal.
        }
    }
#>
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

<#
    if ($result.ExitCode -eq 'NoChangeNeeded')
    {

    }
    else
    {
        write-host $result.ExitCode
        exit
    }
#>