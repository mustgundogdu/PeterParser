    
<#
    This Module Obtain Unique Hash to Export File
    CSV Format

    SHA256 hash Function reference implementation,
    
    This is an annotated direct implementation of FIPS 180-4 , without any optimisations , It is 
    intented to aid understanding of the algorithm rather than for production use.

    Generate SHA algorithm result on "/LocalStorage/Date.hlog",
    And Backup ShA algorithm result with Timestamp "/Backup/Date.hlog"

    Author: @b3kc4t

#> 

function Sha256CsvExport
    {
        param($LogTimeSearch, $Sha256hash, $ShareName)
        $computerName = $env:COMPUTERNAME
        $BackupFileName = $computerName + "_LoggingHashs256Backup" + "+" + (Get-Date).ToString("yyyy-MM-dd") + ".csv"
        $FileName = $computerName + "_LoggingHashs256" + "+" + (Get-Date).ToString("yyyy-MM-dd") + ".csv"
        
        # Backup File Check
        BackupFileCheck $BackupFileName
        
        # File Check Func.
        $ResultFileCheck = ShareFileCheck $FileName $ShareName
        if ($ResultFileCheck -eq 'OK Share Folder')
            {
                $csvHashing = @{
                    SHA256Hash = $Sha256hash
                    TimeStamp = $LogTimeSearch
                }

                $resultObj = New-Object PSObject -Property $csvHashing

                try
                    {
                        $resultforwrite = BackupFileWrCheck $BackupFileName
                        if ($resultforwrite -eq 'OK Write')
                            {
                                $resultObj | Export-Csv -Path .\LocalStorage\backup\$BackupFileName -NoTypeInformation -Append
                            }
                        
                        $resultObj | Export-Csv -Path $ShareName\$FileName -NoTypeInformation -Append
                    }
                catch
                    {
                        Write-Output 'Write Error'
                    }
            }
    }

function Sha512CsvExport
    {
        param($LogTimeSearch, $Sha512hash, $ShareName)
        $computerName = $env:COMPUTERNAME
        $BackupFileName = $computerName + "_LoggingHashs512Backup" + "+" + (Get-Date).ToString("yyyy-MM-dd") + ".csv"
        $FileName = $computerName + "_LoggingHashs512" + "+" + (Get-Date).ToString("yyyy-MM-dd") + ".csv"
        # Backup File Check
        BackupFileCheck $BackupFileName
        

        # File Check Func.
        $ResultFileCheck = ShareFileCheck $FileName $ShareName
        if ($ResultFileCheck -eq 'OK Share Folder')
            {
                $csvHashing = @{
                    SHA512Hash = $Sha512hash
                    TimeStamp = $LogTimeSearch
                }

                $resultObj = New-Object PSObject -Property $csvHashing

                try
                    {
                        $resultforwrite = BackupFileWrCheck $BackupFileName
                        if ($resultforwrite -eq 'OK Write')
                            {
                                $resultObj | Export-Csv -Path .\LocalStorage\backup\$BackupFileName -NoTypeInformation -Append
                            }

                        $resultObj | Export-Csv -Path $ShareName\$FileName -NoTypeInformation -Append
                    }
                catch
                    {
                        Write-Output 'Write Error'
                    }
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

function BackupFileWrCheck
    {
        param($BackupFileName)
        $checkBackupFile = Test-Path .\LocalStorage\backup\$BackupFileName -PathType Leaf
        if ($checkBackupFile -eq $true)
            {
                return 'OK Write'
            }
        elseif ($checkBackupFile -eq $false)
            {
                 New-Item -Path .\LocalStorage\backup\ -Name $BackupFileName -ItemType "file"
                 return 'OK Write'
            }
    }

function ShareFileCheck
    {
        param($FileName, $ShareName)
        # Check File Name On Storage
        $checkexistFileShare = Test-Path $ShareName\$FileName -PathType Leaf
        if ($checkexistFileShare -eq $true)
            {
                return 'OK Share Folder'
            }
        else
            {
            
                New-Item -Path $ShareName\ -Name $FileName -ItemType "file"
                return 'OK Share Folder'
            }
    }

function ShareHashFile
    {
        param($FileName, $ShareName)
        # Check File Name on Share Folder
        $checkexistFShare = Test-Path $ShareName\$FileName -PathType Leaf
        if ($checkexistFShare -eq $true)
            {
                return 'OK Hash File On Share Folder'
            }
        else
            {
                New-Item -Path $ShareName\ -Name $FileName -ItemType "file"
                return 'OK Hash File On Share Folder'
            }
    }
