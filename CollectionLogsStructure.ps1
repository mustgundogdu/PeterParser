<#
    SEQUENCER LOG COLLECT FROM EVENT IDS
    Author : @b3kc4t

     * Kerberoasting
      ||
      \/
     * PassTHeTicket
      ||
      \/
     * PassTheHash
      
    PassTheTicket WCurrent User Sessions 
    
#>
## Import Modules
 . ".\ErrorM\systemErr.ps1"
 . ".\Kerberoasting.ps1"
 . ".\passTheHash.ps1"
 . ".\passTheTicket.ps1"
 . ".\ShareCheck\shareChecking.ps1"
 . ".\LocalStorage\AgentTime.ps1"
 . ".\LocalStorage\StorageHashCheck.ps1"
 
function ComputerCheck
    {
        $osInf = Get-CimInstance -ClassName Win32_OperatingSystem
        # Check OS Type
        ## Domain Controller : 2, WorkStation : 1

        ### Workstation Detection 
        if ($osInf.ProductType -eq 1)
            {
                $osType = "Workstation"
                return $osType
            }
        ### Domain Controller 
        elseif ($osInf.ProductType -eq 2)
            {
                $osType = "Domain Controller"
                return $osType
            }
        ### Windows Server
        elseif ($osInf.ProductType -eq 3)
            {
                $osType = "Server"
                return $osType
            }
        ### Unknown Type (No Execute)
        elseif ($osInf.ProductType -eq 0)
            {
                $osType = "Unknown"
                return $osType
            }

        
    }

function CreateShaHasForStartTime

     {
        param([String]$PlainTextTime)
        $HasherTime = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
        $hashTime = $HasherTime.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($PlainTextTime))
        # Encryption with Sha256
        $HashTextForTime = [System.BitConverter]::ToString($hashTime)
        $EncryptToHashTime = $HashTextForTime.Replace('-','')
        
        return $EncryptToHashTime
     } 

function StartTimeLogExport
    {   
        param($ShareName, $StartTime, $FinishTime)
        $computerName = $env:COMPUTERNAME
        $ExpStartFile = $computerName + '_CollectionStartTime' + "+" + (Get-Date).ToString("yyyy-MM-dd") + ".csv"
        # Hash Value
        $Sha256hasForTimeBegin = CreateShaHasForStartTime $StartTime
        # TimeStamp Value 
        $TimeStampVal = (Get-Date).ToString("yyyy-MM-dd-hh-mm")

        # Check file Name on Path
        $checkexistFile = Test-Path $ShareName\$ExpStartFile -PathType Leaf
    
        if ($checkexistFile -eq $false){
            #Create File 
        
            New-Item -Path $ShareName\ -Name $ExpStartFile -ItemType "file" -Value "This is a Log File"

        }

        ## EXPORT TO FILE   ##
         #                  #
         $ArrayOfTime = @()
         [System.Collections.ArrayList]$ListOfStartTime = @($StartTime, $FinishTime, $Sha256hasForTimeBegin, $TimeStampVal)
         # Default Columns 
         [System.Collections.ArrayList]$TimePerceptronEvents = @(
                "StartTime",
                "FinishTime",
                "HashValue",
                "TimeStamp"
         
         )

         # Remove Null Item
        For ($lenTime=0; $lenTime -lt $ListOfStartTime.Count; $lenTime++)
            {
                if ($ListOfStartTime[$lenTime].Length -eq 0)
                    {
                        $ArrayOfTime += $TimePerceptronEvents[$lenTime]
                        $TimePerceptronEvents.RemoveAt($lenTime)
                        $ListOfStartTime.RemoveAt($lenTime)
                        $lenTime--
                    }
            }


         # Check Value 
        if ($ArrayOfTime -ne $null)
            {
                
                $msgofStartTimeEvent = 'Event Type is ' + $ArrayOfTime + ' None'
                StartTimeEventType $msgofStartTimeEvent $computerName
            }

        if ($ListOfStartTime -eq $null)
            {
                $computerName = $env:COMPUTERNAME
                $msgofStartTimeEvent = 'All Event is None'
                StartTimeEventType $msgofStartTimeEvent $computerName
            }

        if ($ListOfStartTime -ne $null)
            {
                ## Adding Update
                $resultOfTimePercp = @()
                For ($lenAllS=0; $lenAllS -lt $ListOfStartTime.Count; $lenAllS++)
                    {
                        $StartTimeRes += @{$TimePerceptronEvents[$lenAllS] = ($ListOfStartTime[$lenAllS] -join ',')}
                        $resultOfTimePercp = New-Object PSObject -Property $StartTimeRes
                    }

                    try
                        {
                            $resultOfTimePercp | Export-Csv -Path $ShareName\$ExpStartFile -NoTypeInformation -Force
                            
                        }
                    catch
                        {
                            # Call Error
                            $noExportEvent = 'NotWork'
                            StartTimeEventType $noExportEvent $computerName
                        }

                Sha256CsvExport $TimeStampVal $Sha256hasForTimeBegin $ShareName
            }




    }


function SequencerLogCollection
    {
        # Check COmputer Type
        $cType = ComputerCheck

        if ($cType -eq 'Unknown')
            {
                notSupportErr $cType
            }
        else
            {
                <#
                    SEQUENCER ATTACK Detection
                    Domain Controller :
                    Kerberoasting Events

                #>
                if ($cType -eq 'Domain Controller')
                    {
                        # Find Share Folder
                        $ShareName = CheckShareOnDC
                        $Delay = 300
                        
                        # Start Time
                        #$StartTime = ((Get-Date).Hour.ToString() +':'+ (Get-Date).Minute.ToString())
                        #Write-Output $StartTime
                        
                        ### Time Counter
                        while ($Delay -ge 0)
                            {
                                # Start Time 
                                $StartTime = ((Get-Date).Hour.ToString() +':'+ (Get-Date).Minute.ToString())
                                #Write-Output $StartTime
                                ShareAgentCollect
                                # Counter Of 1 Second        
                                Start-Sleep -Seconds 1
                                $Delay -= 1
                                # Mod Operator For 5 Minutes
                                if ($Delay%60 -eq 0)
                                    {
                                        <#
                                            - PassTheTicket Monitoring Of Session Users LOG -
                                         #>

                                        LoggedUser
                                    }
                                        
                                
                                if ($Delay -eq 0)
                                    {   
                                        $LogCollectTime = (Get-Date).addMinutes(-5)
                                        <# 
                                            - Kerberoasting Detection LOG -
                                         #>
                                        EventIdKerb $ShareName $LogCollectTime

                                        <#
                                            - LOG Event IDS 4624, 4672 -
                                         #>
                                  
                                        EventIdSystemSuccessLogon $ShareName $LogCollectTime
                                        EventIdSystemPrivelegeLogon $ShareName $LogCollectTime

                                        <# 
                                            - LOG Event ID 4768(TGT) -
                                         #>
                                        EventTgTProcess $ShareName $LogCollectTime
                                        EventTgSProcess $ShareName $LogCollectTime

                                        
                                        # Finish Collect Time
                                        $FinishTime = ((Get-Date).Hour.ToString() +':'+ (Get-Date).Minute.ToString())
                                        Write-Output $FinishTime
                                        # Call Func.
                                        StartTimeLogExport $ShareName $StartTime $FinishTime
                                        $Delay = 300
                                    }    
                            
                            }
                             

                    }

                ## Windows Server ## 
                elseif ($cType -eq 'Server')
                    {
                         # Find Share Folder
                         $ShareName = CheckShareOnServer
                         $Delay = 1500 

                         # Start Time
                         #$StartTime = ((Get-Date).Hour.ToString() + ':' + (Get-Date).Minute.ToString())

                         ### Time Counter
                         while ($Delay -ge 0)
                            {
                                # Start Time 
                                $StartTime = ((Get-Date).Hour.ToString() + ':' + (Get-Date).Minute.ToString())
                                # Counter Of 1 Second
                                Start-Sleep -Seconds 1
                                $Delay -= 1
                                # Mod Operator For 5 Minutes 
                                if ($Delay%300 -eq 0)
                                    {
                                        <#
                                            - PassTheTicket Monitoring Of Session Users LOG -
                                        #> 
                                        LoggedUser
                                    }

                                    if ($Delay -eq 0)
                                        {
                                            $LogCollectTime = (Get-Date).addMinutes(-25)
                                            <#
                                                - Kerberoasting Detection LOG -
                                            #>
                                            EventIdKerb $ShareName $LogCollectTime
                                            <# 
                                                - LOG Event ID 4768(TGT) -
                                            #>
                                            EventTgTProcess $ShareName $LogCollectTime
                                            EventTgSProcess $ShareName $LogCollectTime

                                            <#
                                                - LOG Event IDS 4648, 4624, 4672 -
                                            #>
                                            EventIdSystemLogon $ShareName $LogCollectTime
                                            EventIdSystemSuccessLogon $ShareName $LogCollectTime
                                            EventIdSystemPrivelegeLogon $ShareName $LogCollectTime

                                            $Delay = 1500
                                        }
                            }

                    }

                ### Workstation ###
                elseif ($cType -eq 'Workstation')
                    {
                        # Find Share Folder
                        $ShareName = ChackShareOnWorkstation
                        $Delay = 1500

                        # Start Time
                        $StartTime = ((Get-Date).Hour.ToString() + ':' + (Get-Date).Minute.ToString())

                        ### Time Counter
                        while ($Delay -ge 0)
                            {
                                # Counter of 1 Second 
                                Start-Sleep -Seconds 1
                                $Delay -= 1
                                # Session User PassTheTicket
                                if ($Delay%300 -eq 0)
                                    {
                                        <#
                                           - PassTheTicket Monitoring of Session Users LOG -
                                        #>
                                        LoggedUser
                                    }

                                if ($Delay -eq 0)
                                    {
                                        $LogCollectTime = (Get-Date).addMinutes(-25)
                                        <#
                                            - Pass The Hash LOG Event IDS 4648, 4624, 4672 - 
                                        #>
                                        EventIdSystemLogon $ShareName $LogCollectTime
                                        EventIdSystemSuccessLogon $ShareName $LogCollectTime
                                        EventIdSystemPrivelegeLogon $ShareName $LogCollectTime

                                        $Delay = 1500
                                    }
                            }

                    
                    }
            }
    }


 
SequencerLogCollection