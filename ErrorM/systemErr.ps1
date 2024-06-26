## EventId Export Not Working Error

function notExportToCsv
    {
        param([string]$noworkCsv, [string]$ValExpTicket)
        $date = TimeCheck
        # Check Value 
        if ($noworkCsv -eq 'NotWork')
            {
                $jsonBaseExp = @{
                    Message = $ValExpTicket
                    Time = $date
                }
                $objJs = [PSCustomObject]$jsonBaseExp
                ExportToJson $objJs
            }
        
    }

## Microsoft Unsupport Errors
function notSupportErr
    {
        param([string]$noSupArg)
        $date = TimeCheck
        # System Support Check
        if ($noSupArg -eq 'Unknown')
            {
               $jsonBase = @{
                    Message = "This Operating System is Unknown"
                    ProductType = 0
                    Time = $date

               }
               $oJson = [PSCustomObject]$jsonBase
               ExportToJson $oJson
                
            }
    }

function ExportToJson
    {
        param([string]$arg)
        $computerName = $env:COMPUTERNAME
        $FileName = $computerName + '_ErrorMsg' + '.json'
        FileCheck $FileName
      
        $arg | ConvertTo-Json | Out-File .\ErrorM\$FileName -Append  
         
    }


function FileCheck
    {
        param($FileName)
        # Check file Name on Path
        $checkexistFile = Test-Path .\ErrorM\$FileName -PathType Leaf
        if ($checkexistFile -eq $false)
            {
                #Create File 
                New-Item -Path .\ErrorM\ -Name $FileName -ItemType "file" -Value "This is a Error Json File"
                
            }
            
    }

function TimeCheck
    {
        $date = (get-date).toString("r")
        return $date
    }


function StartTimeEventType
    {
        param($ErrorTimeMsg, $computerName)
        $date = (get-date).toString("r")
        
        $JsonPercTime = $computerName + '_ErrorMsg' + '.json'
        # File Check
        FileCheck $FileName
        $jsonBase = @{
                    Message = $ErrorTimeMsg
                    Time = $date

               }
        $oJson = [PSCustomObject]$jsonBase
        $oJson | Out-File .\ErrorM\$FileName -Append

    }