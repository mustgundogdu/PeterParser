# Import Modules
. ".\workstation\eventsObtainPtH.ps1"
. ".\ErrorM\systemErr.ps1"
. ".\LogF\LogToScr.ps1"


## Event Id (4648)
function EventIdSystemLogon
    {
        param($ShareName, $LogCollectTime)
        $computerName = $env:COMPUTERNAME
        $FileName = $computerName + "_EventPTH4648Log" + "+" + (Get-Date).ToString("yyyy-MM-dd") + ".csv"
        EventIdsLogonPtHProcess $ShareName $FileName $LogCollectTime
        
    }
## Event Id (4624)
function EventIdSystemSuccessLogon
    {
        param($ShareName, $LogCollectTime)
        $computerName = $env:COMPUTERNAME
        $FileName = $computerName + "_EventPTH4624Log" + "+" + (Get-Date).ToString("yyyy-MM-dd") + ".csv"
        EventIdsAccountSuccessPtHProcess $ShareName $FileName $LogCollectTime
    }

## Event Id (4672)
function EventIdSystemPrivelegeLogon
    {
        param($ShareName, $LogCollectTime)
        $computerName = $env:COMPUTERNAME
        $FileName = $computerName + "_EventPTH4672Log" + "+" + (Get-Date).ToString("yyyy-MM-dd") + ".csv"
        SpecialPrivilegesEventProcess $ShareName $FileName $LogCollectTime
    }

