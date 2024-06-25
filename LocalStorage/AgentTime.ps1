
function ShareAgentCollect
    {
        $computerName = $env:COMPUTERNAME
        $BackupFileName = $computerName + "_LoggingHashs256Backup" + "+" + (Get-Date).ToString("yyyy-MM-dd") + ".csv"
        $BackupFileName1 = $computerName + "_LoggingHashs512Backup" + "+" + (Get-Date).ToString("yyyy-MM-dd") + ".csv"
        BackupFileCheck $BackupFileName 
        BackupFileCheck $BackupFileName1

        $HourlyTime = HourlyCheck
        if ($HourlyTime -eq 'Share To Agent')
            {
                # Backup Hashing Fİle Copy To Share Folder
                Copy-Item -Path .\LocalStorage\backup\$BackupFileName -Destination $ShareName -Recurse
                Copy-Item -Path .\LocalStorage\backup\$BackupFileName1 -Destination $ShareName -Recurse
            }
    }


function BackupFileCheck
    {
        param($BackupFileName)
        $checkBackupFile = Test-Path .\LocalStorage\backup\$BackupFileName -PathType Leaf

        if ($checkBackupFile -eq $false)
            {
                # Create File
                New-Item -Path .\LocalStorage\backup\ -Name $BackupFileName -ItemType "file"
                
            }

    }


function HourlyCheck
    {
        $hourlyMinute = (Get-Date).Minute
        if ($hourlyMinute -eq 00 -or $hourlyMinute -eq 01 )
            {
                return 'Share To Agent'
            }
    }