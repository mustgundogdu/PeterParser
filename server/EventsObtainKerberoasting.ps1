# Import Modules
. ".\ErrorM\systemErr.ps1"
. ".\LogF\LogToScr.ps1"

function EventIdKerberoastingProcess
    {
        param([String]$ShareName, $FileName)
        ## Event ID 4769 Account , Additional, Network Logs
        $KerberoastWorkEvent = Get-EventLog -LogName Security -InstanceId 4769 -After (Get-Date).addMinutes(-15)
        EventKerbfileCheck $ShareName $FileName
        For ($c=3; $c -le 18;$c++)
            {
                $splitKerberoastingInf = $KerberoastWorkEvent | % {$_.Message.Split("`n")[$c].split()[4]}
                # Account Name Inf.
                if ($c -eq 3)
                    {
                        $AccountName = $splitKerberoastingInf
                    }
                # Account Domain Inf.
                if ($c -eq 4)
                    {
                        $AccountDomain = $splitKerberoastingInf
                    }
                # Logon GUID Inf.
                if ($c -eq 5)
                    {
                        $LogonGuid = $splitKerberoastingInf
                    }
                # Service Name Inf.
                if ($c -eq 8)
                    {
                        $ServiceName = $splitKerberoastingInf
                    }
                # ServiceID Inf.
                if ($c -eq 9)
                    {
                        $ServiceID = $splitKerberoastingInf
                    }
                # Client Address Inf.
                if ($c -eq 12)
                    {
                        $ClientAddress = $splitKerberoastingInf
                    }
                # Client Port Inf.
                if ($c -eq 13)
                    {
                        $ClientPort = $splitKerberoastingInf
                    }
                # Ticket Options Inf.
                if ($c -eq 16)
                    {
                        $Ticketoptions = $splitKerberoastingInf
                    }
                # Ticket Encryption Type Inf.
                if ($c -eq 17)
                    {
                        $TicketEncType = $splitKerberoastingInf
                    }
                # Failure COde Inf.
                if ($c -eq 18)
                    {
                        $FailureCode = $splitKerberoastingInf
                    }

            }

            # call
            KerberoastingProcessExp $AccountName $AccountDomain $LogonGuid $ServiceName $ServiceID $ClientAddress $ClientPort $Ticketoptions $TicketEncType $FailureCode $ShareName $FileName
    }

function EventKerbfileCheck
    {
        param($ShareName, $FileName)
        # Check File Name On Path
        $checkexistFile = Test-Path $ShareName\$FileName -PathType Leaf
        if ($checkexistFile -eq $false)
            {
                New-Item -Path $ShareName\ -Name $FileName -ItemType "file" 
            }
    }

###################################### EXPORTING ############################################

function KerberoastingProcessExp
    {
        param($AccountName, $AccountDomain, $LogonGuid, $ServiceName, $ServiceID, $ClientAddress, $ClientPort, $Ticketoptions, $TicketEncType, $FailureCode, $ShareName, $FileName)
        # List Of Arguments 
        [System.Collections.ArrayList]$listOfKerberoasting = @($AccountName, $AccountDomain, $LogonGuid, $ServiceName, $ServiceID, $ClientAddress, $ClientPort, $Ticketoptions, $TicketEncType, $FailureCode)
        $kerberoastingEventM = @()
        # Default 4769 Event Types [10]
        [System.Collections.ArrayList]$KerberoastingEventTypes = @(
            "AccountName",
            "AccountDomain",
            "LogonGUID",
            "ServiceName",
            "ServiceID",
            "ClientAddress",
            "ClientPort",
            "TicketOptions",
            "TicketEncryptionType",
            "FailureCode"

        )

        # Remove Null Item
        For ($lenkerbEvent=0; $lenkerbEvent -lt $listOfKerberoasting.Count; $lenkerbEvent++)
            {
                if ($listOfKerberoasting[$lenkerbEvent].Length -eq 0)
                    {
                        $kerberoastingEventM += $KerberoastingEventTypes[$lenkerbEvent]
                        $KerberoastingEventTypes.RemoveAt($lenkerbEvent)
                        $listOfKerberoasting.RemoveAt($lenkerbEvent)
                        $lenkerbEvent--
                        
                    }
            }
        # Check Value
        if ($kerberoastingEventM -ne $null)
            {
                $computerName = $env:COMPUTERNAME
                $msgOfKerborastingEvent = 'Event Type is ' + $kerberoastingEventM + 'None'
                EventTypeStatus $msgOfKerborastingEvent $computerName
            }

        if ($listOfKerberoasting -eq $null)
            {
                $computerName = $env:COMPUTERNAME
                $msgOfKerborastingEvent = 'All Event is None'
                EventTypeStatus $msgOfKerborastingEvent $computerName
            }

        if ($listOfKerberoasting -ne $null)
            {
                ## Adding Update
                $resultOfKerbEvent = @()
                For ($lenAllK=0; $lenAllK -lt $listOfKerberoasting.Count; $lenAllK++)
                    {
                        $EventKerbRes += @{$listOfKerberoasting[$lenAllK] = ($listOfKerberoasting[$lenAllK] -join ',')}
                        $resultOfKerbEvent = New-Object PSObject -Property $EventKerbRes
                    }
                    try
                        {
                            $resultOfKerbEvent | Export-Csv -Path $ShareName\$FileName -NoTypeInformation -Force
                        }
                    catch
                        {
                            # Call Error
                            $noExportEvent = 'NotWork'
                            notExportToCsv $noExportEvent 'Not Export To Logon Values'
                        }
            }
    
    }