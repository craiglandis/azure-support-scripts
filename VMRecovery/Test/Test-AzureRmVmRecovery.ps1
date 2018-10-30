param(
    [string]$userName = 'craig',
    [string]$password = $password,
    [string]$scriptPath = 'C:\src\azure-support-scripts\VMRecovery\ResourceManager'
)

$scriptStartTime = get-date

$tests = get-content -Path "$scriptPath\tests.json" | convertfrom-json

$tests | foreach {
    $test = $_
    $problemVmName = -join (65..90 | Get-Random -Count 3 | % {[char]$_})
    $rescueVmName = "rescue$($problemVmName)"
    $createProblemVmCommand = "new -resourceGroupName $problemVmName -vmName $problemVmName -userName $userName -password $password $($test.createProblemVMCommand)"
    $createRescueVmCommand = "$scriptPath\New-AzureRMRescueVM.ps1 -ResourceGroupName $problemVmName -VmName $problemVmName -userName $userName -password $password $($test.createRescueVmCommand)"
    $removeProblemVmCommand = 'Start-RSjob -Name {$problemVmName} -ScriptBlock {Param($problemVmName);Remove-AzureRmResourceGroup -Name $problemVmName -Force}'
    $removeRescueVmCommand = 'Start-RSjob -Name {$rescueVmName} -ScriptBlock {Param($rescueVmName);Remove-AzureRmResourceGroup -Name $rescueVmName -Force}'
    $startTime = get-date -Date (get-date).ToUniversalTime() -Format yyyy-MM-ddTHH:mm:ssZ

    $test | Add-Member -MemberType NoteProperty -Name 'problemVMName' -Value $problemVmName -Force
    $test | Add-Member -MemberType NoteProperty -Name 'rescueVmName' -Value $rescueVmName -Force
    $test | Add-Member -MemberType NoteProperty -Name 'createProblemVmCommand' -Value $createProblemVmCommand -Force
    $test | Add-Member -MemberType NoteProperty -Name 'createRescueVmCommand' -Value $createRescueVmCommand -Force
    $test | Add-Member -MemberType NoteProperty -Name 'removeProblemVmCommand' -Value $removeProblemVmCommand -Force
    $test | Add-Member -MemberType NoteProperty -Name 'removeRescueVmCommand' -Value $removeRescueVmCommand -Force
    $test | Add-Member -MemberType NoteProperty -Name 'startTime' -Value $startTime -Force
    $test | Add-Member -MemberType NoteProperty -Name 'result' -Value $null -Force

    $testScriptBlock = {
        Invoke-Expression -command $Using:createProblemVMCommand
        Invoke-Expression -command $Using:createRescueVMCommand
        $vm = get-azurermvm -ResourceGroupName $Using:rescueVmName -Name $Using:rescueVmName -ErrorAction Stop

        if ($Using:createRescueVmCommand -match 'enableWinRM')
        {
            $nicId = split-path -Path $vm.NetworkProfile.NetworkInterfaces.Id -Leaf
            $pipId = split-path -Path (Get-AzureRmNetworkInterface -Name $nicId -ResourceGroupName $vm.resourceGroupName -ErrorAction Stop).IpConfigurations.PublicIpAddress.Id -Leaf
            $ip = (Get-AzureRmPublicIpAddress -Name $pipId -ResourceGroupName $vm.resourceGroupName -ErrorAction Stop).IpAddress

            while ($ip -notmatch '(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))') {
                start-sleep -Seconds 15
                $ip = (Get-AzureRmPublicIpAddress -Name $pipId -ResourceGroupName $vm.resourceGroupName -ErrorAction Stop).IpAddress
            }

            $port = '5986'
            $uri = "https://$($ip):$($port)"

            $credential = New-Object System.Management.Automation.PSCredential($Using:userName, $(ConvertTo-SecureString -String $Using:password -AsPlainText -Force))
            $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -NoMachineProfile
            $sessionName = $vm.Name
            $varName = $vm.Name
            remove-pssession -name $sessionName -ErrorAction SilentlyContinue
            remove-variable -name $varName -ErrorAction SilentlyContinue -Force
            $session = New-PSSession -Name $sessionName -ConnectionUri $uri -Credential $credential -SessionOption $sessionOption
            new-variable -Name $varName -Value $session -Scope global -Force

            if ($Using:createRescueVmCommand -match 'enableNestedHyperV')
            {
                $rescueVmScriptBlock = {
                    param(
                        $credential,
                        $nestedVmName
                    )

                    # Added sleep because nested Linux VMs Hyper-V heartbeat was showing as "No contact", need more time to boot?
                    start-sleep -seconds 60
                    get-vm $nestedVmName
                }
                $rescueVmResult = invoke-command -session $session -ScriptBlock $rescueVmScriptBlock -ArgumentList $credential, 'ProblemVM'

                if ($rescueVmResult.Heartbeat -eq 'OkApplicationsUnknown')
                {
                    "PASSED: $($rescueVmResult.Heartbeat)"
                }
                else
                {
                    "FAILED: $($rescueVmResult.Heartbeat)"
                }
            }
            else {
                $rescueVmScriptBlock = {
                    param(
                        $credential,
                        $nestedVmName
                    )

                    get-disk -FriendlyName 'Msft Virtual Disk'
                }
                $rescueVmResult = invoke-command -session $session -ScriptBlock $rescueVmScriptBlock -ArgumentList $credential, 'ProblemVM'

                if ($rescueVmResult.HealthStatus -eq 'Healthy')
                {
                    "PASSED: $($rescueVmResult.HealthStatus)"
                }
                else
                {
                    "FAILED: $($rescueVmResult.HealthStatus)"
                }
            }
        }
        else
        {
            $dataDiskCount = ($vm.storageprofile.datadisks | measure).count
            if ($dataDiskCount -eq 1)
            {
                "PASSED"
            }
            else
            {
                "FAILED"
            }
        }
    }

    $job = Start-RSJob -Name $test.name -ScriptBlock $testScriptBlock
    $test | Add-Member -MemberType NoteProperty -Name job -Value $job -Force
}

$global:debugtests = $tests

do {

    $tests | foreach {
        $test = $_
        $global:debugtest = $test

        $logFilePath = (get-childitem -Path "$scriptPath\New-AzureRMRescueVM_$($test.problemVMName)*.log").Fullname
        if ($logFilePath -and (test-path -Path $logFilePath))
        {
            $logFileContents = get-content -Path $logFilePath
            $test | Add-Member -MemberType NoteProperty -Name 'logFilePath' -Value $logFilePath -Force
            $test | Add-Member -MemberType NoteProperty -Name 'logFileContents' -Value $logFileContents -Force
            $test | Add-Member -MemberType NoteProperty -Name 'logFileLastLine' -Value $logFileContents[-1] -Force
        }

        if (($test.job.Completed -eq $true) -and ($test.endTime -eq $null))
        {
            $endTime = get-date -Date (get-date).ToUniversalTime() -Format yyyy-MM-ddTHH:mm:ssZ
            $duration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $test.startTime -End $endTime)
            $test | Add-Member -MemberType NoteProperty -Name 'endTime' -Value $endTime -Force
            $test | Add-Member -MemberType NoteProperty -Name 'duration' -Value $duration -Force
        }
        elseif ($test.job.Completed -ne $true)
        {
            $currentTime = get-date -Date (get-date).ToUniversalTime() -Format yyyy-MM-ddTHH:mm:ssZ
            $duration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $test.startTime -End $currentTime)
            $test | Add-Member -MemberType NoteProperty -Name 'duration' -Value $duration -Force
        }
    }
    $tests | format-table Name, problemVmName, rescueVmName, startTime, endTime, duration, @{Label='state'; Expression={$_.job.State}}, @{Label='error'; Expression={$_.job.Error}}, logFileLastLine -AutoSize
    start-sleep -seconds 15

} until (($tests | where endTime -eq $null | measure).Count -eq 0)

$tests | foreach {$test = $_;$result = $test.job | receive-rsjob}

$tests | foreach {
    $test = $_
    $global:debugtest = $test
    $result = $test.job | receive-rsjob
    $test | Add-Member -MemberType NoteProperty -Name 'result' -Value $result -Force
    $logFilePath = (get-childitem -Path "$scriptPath\New-AzureRMRescueVM_$($test.problemVMName)*.log").Fullname
    if (test-path -Path $logFilePath)
    {
        $logFileContents = get-content -Path $logFilePath
        $test | Add-Member -MemberType NoteProperty -Name 'logFilePath' -Value $logFilePath -Force
        $test | Add-Member -MemberType NoteProperty -Name 'logFileContents' -Value $logFileContents -Force
        $test | Add-Member -MemberType NoteProperty -Name 'logFileLastLine' -Value $logFileContents[-1] -Force
    }
}

$tests | format-table Name, result, problemVmName, rescueVmName, startTime, endTime, duration, @{Label='error'; Expression={$_.job.Error}}, logFileLastLine -AutoSize

$resultsFilePath = "$scriptPath\testresult_$(get-date -Format yyyMMddhhmmss).xlsx"
$tests | Export-Excel -Path $resultsFilePath
invoke-item -Path $resultsFilePath

$scriptEndTime = get-date
$scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End $scriptEndTime)
write-host "Completed $($tests.count) in $scriptDuration"

# cleanup
# get-childitem cert:\currentuser\my | where subject -match 'winrm' | foreach{remove-item $_.PSPath}
#(vms).Name | where {$_ -notmatch 'RLGUESTRESTART' -and $_ -notmatch 'RLWITHCRASH' -and $_ -notmatch 'RLWITHOUTCRASH'} | foreach {nuke $_}