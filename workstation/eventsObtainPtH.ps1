# Import Modules
. ".\ErrorM\systemErr.ps1"
. ".\LogF\LogToScr.ps1"
. ".\HashCreate.ps1"
. ".\LocalStorage\StorageHashCheck.ps1"

function EventIdsLogonPtHProcess
    {
        param([String]$ShareName, $FileName, $LogCollectTime)
        
        ## EventID 4648 Account, Additional, Network Logs
        $logonWorkevents = Get-EventLog -LogName security -InstanceId 4648 -After $LogCollectTime
        EventPtHfileCheck $ShareName $FileName

        For ($i=3; $i -le 24; $i++)
            {
                $splitEPthInf = $logonWorkevents | % {$_.Message.Split("`n")[$i].split()[4]}
                # Security ID Inf.
                if ($i -eq 3)
                    {
                        $SecurityID = $splitEPthInf
                    }
                # Account Name Inf.
                if ($i -eq 4)
                    {
                        $AccountName = $splitEPthInf
                    }
                # Account Domain Inf.
                if ($i -eq 5)
                    {
                        $AccountDomain = $splitEPthInf
                    }
                # Logon ID Inf.
                if ($i -eq 6)
                    {
                        $LogonID = $splitEPthInf
                    }
                # Logon GUIF Inf.
                if ($i -eq 7)
                    {
                        $LogonGuid = $splitEPthInf
                    }
                ## Account Whose Credentials were Used
                #Account Name
                if ($i -eq 10)
                    {
                        $UsedAccountName = $splitEPthInf
                    }
                # Account Domain 
                if ($i -eq 11)
                    {
                        $UsedDomainName = $splitEPthInf
                    }
                # Logon GUID
                if ($i -eq 12)
                    {
                        $UsedLogonGuid = $splitEPthInf
                    }
                # Target Server Name
                if ($i -eq 15)
                    {
                        $TargetServerName = $splitEPthInf
                    }
                ## Additional Information
                if ($i -eq 16)
                    {
                        $splitEPthree = $logonWorkevents | % {$_.Message.Split("`n")[16].split()[3]}
                        $additionalInf = $splitEPthree

                    }

                # Process ID
                if ($i -eq 19)
                    {
                        $ProcessId = $splitEPthInf
                    }
                # Process Name
                if ($i -eq 20)
                    {
                        $ProcessName = $splitEPthInf
                    }

                ## Network Address
                if ($i -eq 23)
                    {
                        $splitEPthreeT = $logonWorkevents | % {$_.Message.Split("`n")[23].split()[3]}
                        $networkAddress = $splitEPthreeT

                    }

                # Port 
                if ($i -eq 24)
                    {
                         $PortAddr = $splitEPthInf
                    }


            }
        # Create TimeStamp Value
        $TimeStampVal = (Get-Date).ToString("yyyy-MM-dd-hh-mm")
        $TimeStampValHash = $TimeStampVal + '_EventPTH4648Log'

        # Unique Hash
        $Sha512Hash = CreateHashSha512 $TimeStampVal

        # Call 
        LogonEventProcess $SecurityID $AccountName $AccountDomain $LogonID $LogonGuid $UsedAccountName $UsedDomainName $UsedLogonGuid $TargetServerName $additionalInf $ProcessId $ProcessName $networkAddress $PortAddr $Sha512Hash $TimeStampVal $ShareName $FileName


    }

function EventIdsAccountSuccessPtHProcess
    {
        param([String]$ShareName, $FileName, $LogCollectTime)
        ## EventID 4624 Account, Additional, Network Logs
        $accountSuccesswork = Get-EventLog -LogName security -InstanceId 4624 -After $LogCollectTime
        EventPtHfileCheck $ShareName $FileName

        For ($countE1=3; $countE1 -le 40; $countE1++)
            {
                $splitEPthInf1 = $accountSuccesswork | % {$_.Message.Split("`n")[$countE1].split()[4]}
                # Security ID Inf.
                if ($countE1 -eq 3)
                    {
                        $SecurityIDS = $splitEPthInf1
                    }
                # Account Name Inf.
                if ($countE1 -eq 4)
                    {
                        $AccountNameS = $splitEPthInf1
                    }
                # Account Domain Inf.
                if ($countE1 -eq 5)
                   {
                       $AccountDomainS = $splitEPthInf1
                   }
                # Logon ID Inf.
                if ($countE1 -eq 6)
                    {
                        $LogonIDS = $splitEPthInf1
                    }
                ## Logon Information
                # Logon Type Inf.
                if ($countE1 -eq 8)
                    {
                        $LogonTypeS = $splitEPthInf1
                    }
                ## New Logon
                # Security ID Inf.
                if ($countE1 -eq 13)
                    {
                        $SecurityIDNewLogon = $splitEPthInf1
                    }
                # Account Name Inf.
                if ($countE1 -eq 14)
                    {
                        $AccuntNameNewLogon = $splitEPthInf1
                    }
                # LogonID Inf.
                if ($countE1 -eq 16)
                    {
                        $LogonIDNewLogon = $splitEPthInf1
                    }
                # Linked Logon ID Inf.
                if ($countE1 -eq 17)
                    {
                        $splitEPthInffive = $accountSuccesswork | % {$_.Message.Split("`n")[21].split()[5]}
                        $LinkedLogonID = $splitEPthInffive

                    }
                # Process ID Inf.
                if ($countE1 -eq 20)
                    {
                        $ProcessIDS = $splitEPthInf1
                    }

                # Process Name Inf.
                if ($countE1 -eq 21)
                    {
                        $ProcessNameS = $splitEPthInf1
                    }

                # Workstation Name Inf.
                if ($countE1 -eq 24)
                    {
                        $splitOthThree = $accountSuccesswork | % {$_.Message.Split("`n")[24].split()[3]}
                        $WorkstationName = $splitOthThree
                    }


                 # Source Network Address ınf.
                if ($countE1 -eq 25)
                    {
                        $SourceNetworkAddr = $splitEPthInf1
                    }
    
                # Source Port Inf.
                if ($countE1 -eq 26)
                    {
                        $SourcePortAddr = $splitEPthInf1
                    }
               
                
                ## Detailed Authentication INformation
                # Logon Process
                if ($countE1 -eq 29)
                    {
                        $LogonProcessS = $splitEPthInf1 
                    }
               
                # Transited Services Inf.
                if ($countE1 -eq 31)
                    {
                        $splitTService = $accountSuccesswork | % {$_.Message.Split("`n")[31].split()[3]}
                        $TransitedService = $splitTService
                    }
                


            }

        ## Create Timestamp Value
        $TimeStampVal = (Get-Date).ToString("yyyy-MM-dd-hh-mm")
        $TimeStampHash = $TimeStampVal + '_EventPTH4624Log'
        $Sha512HashASP = CreateHashSha512 $TimeStampHash
        # Call
        SuccessLogonEventProcess $SecurityIDS $AccountNameS $AccountDomainS $LogonIDS $LogonTypeS $SecurityIDNewLogon $AccuntNameNewLogon $LogonIDNewLogon $LinkedLogonID $ProcessIDS $ProcessNameS $WorkstationName $SourceNetworkAddr $SourcePortAddr $LogonProcessS $TransitedService $Sha512HashASP $TimeStampVal $ShareName  $FileName
   
    }


function SpecialPrivilegesEventProcess
    {
        param([String]$ShareName, $FileName, $LogCollectTime)
        ## EventId 4672 Account, Additional Logs
        $SpecialPrivelegesWork = Get-EventLog -LogName security -InstanceId 4672 -After $LogCollectTime
        EventPtHfileCheck $ShareName $FileName
        For ($countE2=3; $countE2 -le 6; $countE2++)
            {
                $splitEPthInfPrivelege = $SpecialPrivelegesWork | % {$_.Message.Split("`n")[$countE2].split()[4]}
                # Security ID Inf.
                if ($countE2 -eq 3)
                    {
                        $SecurityIDPrivelege = $splitEPthInfPrivelege
                    }
                # Account Name Inf.
                if ($countE2 -eq 4)
                    {
                        $AccountNamePrivelege = $splitEPthInfPrivelege
                    }
                # Account Domain Inf.
                if ($countE2 -eq 5)
                    {
                        $AccountDomainPrivelege = $splitEPthInfPrivelege
                    }
                # LogonID Inf.
                if ($countE2 -eq 6)
                    {
                        $LogonIDPrivelege = $splitEPthInfPrivelege
                    }
            }
        ## Create Timestamp Value
        $TimeStampVal2 = (Get-Date).ToString("yyyy-MM-dd-hh-mm")
        $TimeStampVal2Hash = $TimeStampVal2 + "_EventPTH4672Log"
        $Sha512HashSPP =  CreateHashSha512 $TimeStampVal2Hash

        # Call
        PrivelegeLogonProcess $SecurityIDPrivelege $AccountNamePrivelege $AccountDomainPrivelege $LogonIDPrivelege $Sha512HashSPP $TimeStampVal2 $ShareName $FileName


    }


function EventPtHfileCheck
    {
        param($ShareName, $FileName)
        # Check File Name On Path
        $checkexistFile = Test-Path $ShareName\$FileName -PathType Leaf
        if ($checkexistFile -eq $false)
            {
                New-Item -Path $ShareName\ -Name $FileName -ItemType "file" 
            }
    }


    ###################################  EXPORTING CSV ###########################################
    <#
            This Place is Checking To Specifical EventIds And After Write To Csv File Wtihout Null Values.
            ## EVENT IDS 4648 , 4624, 4672
    
    #>

function SuccessLogonEventProcess
    {
        param($SecurityIDS, $AccountNameS, $AccountDomainS, $LogonIDS, $LogonTypeS, $SecurityIDNewLogon, $AccuntNameNewLogon, $LogonIDNewLogon, $LinkedLogonID, $ProcessIDS, $ProcessNameS, $WorkstationName, $SourceNetworkAddr, $SourcePortAddr, $LogonProcessS, $TransitedService, $Sha512HashASP, $logPthTimeASP, $ShareName, $FileName)
        # List Of Arguments
        [System.Collections.ArrayList]$ListOfSuccessLogon = @($SecurityIDS, $AccountNameS, $AccountDomainS, $LogonIDS, $LogonTypeS, $SecurityIDNewLogon, $AccuntNameNewLogon, $LogonIDNewLogon, $LinkedLogonID, $ProcessIDS, $ProcessNameS, $WorkstationName, $SourceNetworkAddr, $SourcePortAddr, $LogonProcessS, $TransitedService, $Sha512HashASP, $logPthTimeASP)
        $SuccessLogonEventM = @()
        # Default Succes(4624) Logon Event Types [18]
        [System.Collections.ArrayList]$SuccessLogonEventType = @(
            "SecurityID",
            "AccountName",
            "AccountDomain",
            "LogonID",
            "LogonType",
            "SecurityIDNewLogon",
            "AccountNameNewLogon",
            "LogonIDNewLogon",
            "LinkedLogonID",
            "ProcessID",
            "ProcessName",
            "WorkstationName",
            "SourceNetworkAddress",
            "SourceNetworkPort",
            "LogonProcess",
            "TransitedService",
            "HashValue",
            "TimeStamp"
        
        )
       
        # Remove Null Item
        For ($lenSuccessLog=0; $lenSuccessLog -lt $ListOfSuccessLogon.Count; $lenSuccessLog++)
            {
                if ($ListOfSuccessLogon[$lenSuccessLog].Length -eq 0)
                    {
                        $SuccessLogonEventM += $SuccessLogonEventType[$lenSuccessLog]
                        $SuccessLogonEventType.RemoveAt($lenSuccessLog)
                        $ListOfSuccessLogon.RemoveAt($lenSuccessLog)
                        $lenSuccessLog--
                    }
            }
        # Check Value 
        if ($SuccessLogonEventM -ne $null)
            {
                $computerName = $env:COMPUTERNAME
                $msgOfSuccessLogonEvent = 'Event Type is ' + $SuccessLogonEventM + ' None'
                EventTypeStatus $msgOfSuccessLogonEvent $computerName
            }

        if ($ListOfSuccessLogon -eq $null)
            {
                $computerName = $env:COMPUTERNAME
                $msgOfSuccessLogonEvent = 'All Event is None'
                EventTypeStatus $msgOfSuccessLogonEvent $computerName
            }

        if ($ListOfSuccessLogon -ne $null)
            {
                ## Adding Update
                $resultOfSuccessLogon = @()
                For ($lenAllS=0; $lenAllS -lt $ListOfSuccessLogon.Count; $lenAllS++)
                    {
                        $EventSuccessLogonRes += @{$SuccessLogonEventType[$lenAllS] = ($ListOfSuccessLogon[$lenAllS] -join ',')}
                        $resultOfSuccessLogon = New-Object PSObject -Property $EventSuccessLogonRes
                    }

                    try
                        {
                            $resultOfSuccessLogon | Export-Csv -Path $ShareName\$FileName -NoTypeInformation -Force
                            Write-Output $Sha512HashASP
                            Write-Output $logPthTimeASP
                            
                        }
                    catch
                        {
                            # Call Error
                            $noExportEvent = 'NotWork'
                            notExportToCsv $noExportEvent 'Not Export To Logon Values'
                        }


                    # Export TimeStamp Csv
                    
                    Sha512CsvExport $logPthTimeASP $Sha512HashASP $ShareName

            }


    }


function LogonEventProcess
    {
        param($SecurityID, $AccountName, $AccountDomain, $LogonID, $LogonGuid, $UsedAccountName, $UsedDomainName, $UsedLogonGuid, $TargetServerName, $additionalInf, $ProcessId, $ProcessName, $networkAddress, $PortAddr,$Sha512Hash, $logPthTime, $ShareName, $FileName )
        # List Of Arguments
        [System.Collections.ArrayList]$ListOfLogon = @($SecurityID, $AccountName, $AccountDomain, $LogonID, $LogonGuid, $UsedAccountName, $UsedDomainName, $UsedLogonGuid, $TargetServerName, $additionalInf, $ProcessId, $ProcessName, $networkAddress, $PortAddr,$Sha512Hash, $logPthTime)
        $LogonEventM = @()
        # Default Logon(4648) Event Types [14]
        [System.Collections.ArrayList]$LogonEventType = @(
            "SecurityID",
            "AccountName",
            "AccountDomain",
            "LogonID",
            "LogonGuid",
            "UsedAccountName",
            "UsedDomainName",
            "UsedLogonGuid",
            "TargetServerName",
            "AdditionalInformation",
            "ProcessId",
            "ProcessName",
            "NetworkAddress",
            "Port",
            "HashValue",
            "TimeStamp"
        )
        # Remove Null Item
        For ($lenLogonE=0; $lenLogonE -lt $ListOfLogon.Count; $lenLogonE++)
            {
                if ($ListOfLogon[$lenLogonE].Length -eq 0)
                    {
                        $LogonEventM += $LogonEventType[$lenLogonE]
                        $LogonEventType.RemoveAt($lenLogonE)
                        $ListOfLogon.RemoveAt($lenLogonE)
                        $lenLogonE--
                    }
            }

        ## Check Value
        if ($LogonEventM -ne $null)
            {
                $computerName = $env:COMPUTERNAME
                $msgOfLogonEvent = 'Event Types is ' + $LogonEventM + ' None'
                EventTypeStatus $msgOfLogonEvent $computerName
            }
        if ($ListOfLogon -eq $null)
            {
                $computerName = $env:COMPUTERNAME
                $msgOfLogonEvent = 'All Event is None'
                EventTypeStatus $msgOfLogonEvent $computerName
            }
        if ($ListOfLogon -ne $null)
            {
                ## Adding Update 
                $resultOfLogon = @()
                For ($lenAll=0; $lenAll -lt $ListOfLogon.Count; $lenAll++)
                    {
                        $EventLogonRes += @{$LogonEventType[$lenAll] = ($ListOfLogon[$lenAll] -join ',')}
                        $resultOfLogon = New-Object PSObject -Property $EventLogonRes

                    }

                    try
                        {
                            $resultOfLogon | Export-Csv -Path $ShareName\$FileName -NoTypeInformation -Force
                            # Try Sha Hash to Export file
                            Write-Output  $Sha512Hash
                            Write-Output $logPthTime
                            
                        }
                    catch
                        {
                            # Call Error
                            $noExportEvent = 'NotWork'
                            notExportToCsv $noExportEvent 'Not Export To Logon Values'
                        }

                    # Export TimeStamp Csv
                    
                    Sha512CsvExport $logPthTime $Sha512Hash $ShareName
            
            }
    
    
    }

function PrivelegeLogonProcess
    {
        param($SecurityIDPrivelege, $AccountNamePrivelege, $AccountDomainPrivelege, $LogonIDPrivelege,$Sha512HashSPP, $LogTimeSPP, $ShareName, $FileName)
        # List Of Arguments
        [System.Collections.ArrayList]$ListOfPrivelegeLogon = @($SecurityIDPrivelege, $AccountNamePrivelege, $AccountDomainPrivelege, $LogonIDPrivelege,$Sha512HashSPP, $LogTimeSPP)
        $PrivelegeEventM = @()
        #Default PrivelegeLogon (4672) Event Types [4]
        [System.Collections.ArrayList]$PrivelegeLogonEventType = @(
            "SecurityID",
            "AccountName",
            "AccountDomain",
            "LogonID",
            "HashValue",
            "TimeStamp"
        )
        # Remove Null Item
        For ($lenPLogE=0; $lenPLogE -lt $ListOfPrivelegeLogon.Count; $lenPLogE++)
            {
                if ($ListOfPrivelegeLogon[$lenPLogE].Length -eq 0)
                    {
                        $PrivelegeEventM += $PrivelegeLogonEventType[$lenPLogE]
                        $PrivelegeLogonEventType.RemoveAt($lenPLogE)
                        $ListOfPrivelegeLogon.RemoveAt($lenPLogE)
                        $lenPLogE--
                    }
            }
        ## Check Value
        if ($PrivelegeEventM -ne $null)
            {
                $computerName = $env:COMPUTERNAME
                $msgOfLogonPrivelegeEvent = 'Event Types is ' + $PrivelegeEventM + ' None'
                EventTypeStatus $msgOfLogonPrivelegeEvent $computerName
            }
        if ($ListOfPrivelegeLogon -eq $null)
            {
                $computerName = $env:COMPUTERNAME
                $msgOfLogonPrivelegeEvent = 'ALL Event is None'
                EventTypeStatus $msgOfLogonPrivelegeEvent $computerName
            }
        if ($ListOfPrivelegeLogon -ne $null)
            {
                ## Adding Update
                $resultOfPrivelegeLogon = @()
                For ($lenAllP=0; $lenAllP -lt $ListOfPrivelegeLogon.Count; $lenAllP++)

                    {   
                        $EventLogonPrivelegeres += @{$PrivelegeLogonEventType[$lenAllP] = ($ListOfPrivelegeLogon[$lenAllP] -join ',')}
                        $resultOfPrivelegeLogon = New-Object PSObject -Property $EventLogonPrivelegeres
                    }
                    try
                        {
                            $resultOfPrivelegeLogon | Export-Csv -Path $ShareName\$FileName -NoTypeInformation -Force
                            Write-Output $Sha512HashSPP
                            Write-Output $LogTimeSPP
                        }
                    catch
                        {
                            # Call Error
                            $noExportEvent = 'NotWork'
                            notExportToCsv $noExportEvent 'Not Export To Logon Values'
                        }

                    # Export To Timestamp File
                    
                    Sha512CsvExport $LogTimeSPP $Sha512HashSPP $ShareName
            }
    }