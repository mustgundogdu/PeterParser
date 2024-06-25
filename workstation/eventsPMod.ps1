# Import Modules
. "..\ErrorM\systemErr.ps1"
. "..\LogF\LogToScr.ps1"


function LogonEventProcess
    {
        param($SecurityID, $AccountName, $AccountDomain, $LogonID, $LogonGuid, $UsedAccountName, $UsedDomainName, $UsedLogonGuid, $TargetServerName, $additionalInf, $ProcessId, $ProcessName, $networkAddress, $PortAddr, $ShareName, $FileName )
        # List Of Arguments
        [System.Collections.ArrayList]$ListOfLogon = @($SecurityID, $AccountName, $AccountDomain, $LogonID, $LogonGuid, $UsedAccountName, $UsedDomainName, $UsedLogonGuid, $TargetServerName, $additionalInf, $ProcessId, $ProcessName, $networkAddress, $PortAddr)
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
            "Port"
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
                        }
                    catch
                        {
                            # Call Error
                            $noExportEvent = 'NotWork'
                            notExportToCsv $noExportEvent 'Not Export To Logon Values'
                        }
            
            }
    
    
    }

