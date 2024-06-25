 # Import Modules
 . ".\ticketCheck.ps1"
 . ".\ErrorM\systemErr.ps1"
 . ".\dc\eventsObtain.ps1"


function LoggedUser {

    $computerName = $env:COMPUTERNAME
    $fileName = $computerName + '_currentLog.csv'
    $regexa = '.+Domain="(.+)",Name="(.+)"$'
    $regexd = '.+LogonId="(\d+)"$'

    #https://www.ultimatewindowssecurity.com/securitylog/book/page.aspx?spid=chapter3
    $logontype = @{
    
       "0" = "Local System" # 
       "2" = "Interactive" #(Local Logon)
       "3" = "Network" # (Remote Logon)
       "4" = "Batch" # (Scheduled task)  
       "5" = "Service" # (Service account Logon)
       "7" = "Unlock" # (Screen saver)
       "8" = "NetworkCleartext" #(Cleartext network logon)
       "9" = "NewCredentials" #(RunAs using alternate credentials)
       "10" = "RemoteInteractive" # (RDP\TS\RemoteAssistance)
       "11" = "CachedInteractive" # (Local w\cached credentials)

    }

    # Logon Sessions and Username
    $logonSessions = @(gwmi win32_logonsession -ComputerName $computerName)
    $logonUsers = @(gwmi win32_loggedonuser -ComputerName $computerName)

    ## Definations
    $sessionUser = @{}
    $cachedID = @()

    ##Logon User Spliting
    $logonUsers |% {
        $_.antecedent -match $regexa > $nul 
        $username = $matches[1] + "\" + $matches[2]
        $_.dependent -match $regexd > $nul
        $session = $matches[1]
        $sessionUser[$session] += $username
    }
    # File exist checking
    FileCheck $fileName

    $resultCurrentSession = @()
    # Logon Sessions For Hexadecimal 
    $logonSessions |% {
        $startTime = [management.managementdatetimeconverter]::todatetime($_.starttime)
        $sessionHex = ('0x{0:X}' -f [int]$_.LogonId)

        # 
        $CurrentSessionL = @{
            SessionId = $sessionHex
            AccountName = $sessionUser[$_.logonid]
            LogonType = $logontype[$_.logontype.tostring()]
            AuthenticationPackage = $_.authenticationpackage
            StartTime = $startTime
        
        }
        $resultCurrentSession += New-Object PSObject -Property $CurrentSessionL
    
    }
    ProcessOfCsv $resultCurrentSession $fileName

    # Call Ticket Process Function
    ticketProcess $computerName $fileName

}

function ProcessOfCsv{
    param($resultCurrentSession, $fileName)
    
    $resultCurrentSession | Export-Csv -Path $ShareName\$fileName -Force -NoTypeInformation

}

function ticketProcess{

    param($computerName, $fileName)
    $splitCname = @()
    $SessionIDs = @()
    $outputFile = $computerName + "_CachedTicket.csv"

    # Call ReturnSessionsTGTs Func
    ReturnSessionsTGTs $ShareName $fileName
    ##! Check TGTicket file contains
    $sessionOutFile = 'TGTicket.csv'
    $CsvRead = Import-Csv $ShareName\$sessionOutFile

    ## Client Name set
    foreach ($cname in $CsvRead.ClientName)
    {     
        $splitCname += $cname.split()[2] + $cname.split()[4]
        # Check Null Value
        if ($splitCname -eq $null)
        {
            $splitCname += 'None'
        }
    }

    ## SessionID(In hex) 
    foreach ($ses in $CsvRead.SessionID)
    {
        $SessionIDs += $ses
        #Check Null Value
        if ($ses -eq $null)
        {
            $SessionIDs += 'None'
        }
    } 

    if ($splitCname.Length -eq $SessionIDs.Length)
    {
        $resultMatch = @()   
        FileCheck $outputFile 

        try { 
            For ($exp=0; $exp -lt $splitCname.Length; $exp++)
            {
                $MatchSessions = @{
                    AccountName = $splitCname[$exp]
                    SessionID = $SessionIDs[$exp]
                
                }
                
                $resultMatch += New-Object PSObject -Property $MatchSessions 
            }

            $resultMatch | Export-Csv -Path $ShareName\$outputFile -Force -NoTypeInformation
        }
        catch{

            For ($exp=0; $exp -lt $splitCname.Length; $exp++)
            {
                $MatchSessions = @{
                    AccountName = ''
                    SessionID = ''
                }

                $resultMatch += New-Object PSObject -Property $MatchSessions
            }

           $resultMatch | Export-Csv -Path $ShareName\$outputFile -Force -NoTypeInformation
        }

    }
   
    
}

## Event Id 4768
function EventTgTProcess
    {
        param($ShareName, $LogCollectTime)
        $computerName = $env:COMPUTERNAME
        $FileName = $computerName + "_EventTGTLog"+ "+" +(Get-Date).ToString("yyyy-MM-dd") + ".csv"

        TGTLogProcess $ShareName $FileName
    }

## Event Id 4769
function EventTgSProcess
    {
        param($ShareName, $LogCollectTime)
        $computerName = $env:COMPUTERNAME
        $FileName = $computerName + "_EventTGSLog"+ "+" + (Get-Date).ToString("yyyy-MM-dd") + ".csv"

        TGSLogProcess $ShareName $FileName
    }
#! Dont Forget Error Check , Dynamicly process, time control

function FileCheck{
    
    param($ExpFile)
    # Check file Name on Path
    $checkexistFile = Test-Path $ShareName\$ExpFile -PathType Leaf
    
    if ($checkexistFile -eq $false){
        #Create File 
        
        New-Item -Path $ShareName\ -Name $ExpFile -ItemType "file" -Value "This is a Log File"

    }

}
