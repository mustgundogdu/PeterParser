# Import Modules
. ".\dc\eventsObtainKerberoasting.ps1"
. ".\ErrorM\systemErr.ps1"
. ".\LogF\LogToScr.ps1"

## Event Id (4769)
function EventIdKerb
    {
        param($ShareName, $LogCollectTime )
        $computerName = $env:COMPUTERNAME
        $FileName = $computerName + "_EventId4769Log" + "+" + (Get-Date).ToString("yyyy-MM-dd") + '.csv'
        EventIdKerberoastingProcess $ShareName $FileName
        
    }

