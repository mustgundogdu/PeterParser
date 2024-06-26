
function TicketStaus
    {
        param([string]$TGT, [string]$UserHex)
        # Write Log Output
        $FileName = 'TGTLog.csv'
        FileCheck $FileName
        $date = TimeCheck
        # Export To Csv File
        $ExpLog = @{
        
            TicketInformation = $TGT
            UserSessionID = $UserHex
            LogTime = $date
        }
        $objectOfLog = New-Object PSObject -Property $ExpLog
        $objectOfLog | Export-Csv -Path .\LogF\$FileName -Force -NoTypeInformation
    }

function EventTypeStatus
    {
        param([string]$statEvent, [string]$computerName)
        # $FileName = $computerName + '_StatEventId.csv'
        FileCheck $FileName 
        $date = TimeCheck
        # Export To Csv File
        $ExpLogToEvent = @{
            EventInformation = $statEvent
            LogTime = $date
            DCName = $computerName
        }
        
        $objectOfl = New-Object PSObject -Property $ExpLogToEvent
        $objectOfl | Export-Csv -Path .\LogF\$FileName -Force -NoTypeInformation

    }

function TimeCheck
    {
        $date = (get-date).toString("r")
        return $date
    }

function FileCheck
    {
        param($FileName)
        # Check file Name on Path
        $checkexistFile = Test-Path .\LogF\$FileName -PathType Leaf
        if ($checkexistFile -eq $false)
            {
                #Create File 
                New-Item -Path .\LogF\ -Name $FileName -ItemType "file" -Value "This is a Log File"

            }
    
    }

