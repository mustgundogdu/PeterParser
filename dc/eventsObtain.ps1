# Import Modules PassTheTicket
. ".\ErrorM\systemErr.ps1"
. ".\LogF\LogToScr.ps1"
. ".\HashCreate.ps1"
. ".\LocalStorage\StorageHashCheck.ps1"

function TGTLogProcess
    {
        param([String]$ShareName, $FileName)
        
        ## EventID 4768 Account, Additional, Network Logs
        $LogTimeSearchPTT = (Get-Date).addMinutes(-15)
        $kerbSecEvent = Get-EventLog -LogName Security -InstanceId 4768 -After $LogTimeSearchPTT
        FileCheckEvent $ShareName $FileName

        For ($i=3; $i -le 17; $i++)
            {
                $splitEdInf = $kerbSecEvent | % {$_.Message.Split("`n")[$i].Split()[4]}
                #Account Name Inf.
                if ($i -eq 3)
                    {
                        $accountName = $splitEdInf
                    }
                # Supplied Name Inf.
                if ($i -eq 4)
                    {
                        $suppliedName = $splitEdInf
                    }
                # Client Address Inf.
                if ($i -eq 12)
                    {
                        $ClientAddress = $splitEdInf
                    }
                # Client Port Inf.
                if ($i -eq 13)
                    {
                        $ClientPort = $splitEdInf
                    }
                # Ticket Operation Inf.
                if ($i -eq 16)
                    {
                        $ticketopt = $splitEdInf
                    }
                # Result Code Inf.
                if ($i -eq 17)
                    {
                        $resultCode = $splitEdInf
                    }
                # Encryption Type Inf.
                if ($i -eq 18)
                    {
                        $encType = $splitEdInf
                    }

            }

        # Unique Hash
        $TimeStampVal = (Get-Date).ToString("yyyy-MM-dd-hh-mm")
        $TimeStampHash = $TimeStampVal + '_EventTGTLog' 
        $SHA256hash = CreateHashSha $TimeStampHash

        # Call  
        TGTLogProcessExport $kerbSecEvent $accountName $suppliedName $ticketopt $resultCode $encType $ClientAddress $ClientPort $SHA256hash $TimeStampVal $ShareName $FileName
    
    }

function TGTLogProcessExport
    {
        param($EventLength, $accountName, $suppliedName, $ticketopt, $resultCode, $encType, $ClientAddress, $ClientPort, $SHA256hash, $TimeStampVal, $ShareName, $FileName)
        # list Of Arguments 
        [System.Collections.ArrayList]$ListOfTgT = @($accountName, $suppliedName, $ticketopt, $resultCode, $encType, $ClientAddress, $ClientPort, $SHA256hash, $TimeStampVal)
        $EventM = @()
        # Default TgT Event Types
        [System.Collections.ArrayList]$EventType = @(
            "AccountName",
            "SuppliedName",
            "TicketOperation",
            "ResultCode",
            "EncryptionType",
            "ClientAddress",
            "ClientPort",
            "HashValue",
            "TimeStamp"
        )
        # Remove Null Item
        For ($lenE=0; $lenE -lt $ListOfTgT.Count; $lenE++ )
            {
                if ($ListOfTgT[$lenE].Length -eq 0)
                    {
                        $EventM += $EventType[$lenE]
                        $EventType.RemoveAt($lenE)
                        $ListOfTgT.RemoveAt($lenE)
                        $lenE--
                    }
            }


        ## Check Value 
        if ($EventM -ne $null)
            {   $computerName = $env:COMPUTERNAME
                $msgOfEvent = 'Event Types is ' + $EventM + ' None'
                EventTypeStatus $msgOfEvent $computerName 
            }

        if ($ListOfTgT -eq $null)
            {
                $computerName = $env:COMPUTERNAME
                $msgOfEvent = 'All Event is None '
                EventTypeStatus $msgOfEvent $computerName 
            }
        if ($ListOfTgT -ne $null)
            {
        
                ## Adding Update         
                $resultTgT = @()
                For ($lenT=0; $lenT -lt $ListOfTgT.Count; $lenT++)
                    {
                
                        $EventTgTRes += @{$EventType[$lenT] = ($ListOfTgT[$lenT] -join ',')}

                        $resultTgT = New-Object PSObject -Property $EventTgTRes
                 
                    }
        
                try
                    {
                        $resultTgT| Export-Csv -Path $ShareName\$FileName -NoTypeInformation -Force

                        ## Call Storage Export Process and File Create
                        Write-Output $SHA256hash
                        
                    }

                catch
                    {
                        # Call Error
                        $noExportWork = 'NotWork'
                        notExportToCsv $noExportWork 'Not Export To TgT values'
                    }


                # Export Timestamp and SHA HAsh
                Sha256CsvExport $TimeStampVal $SHA256hash $ShareName


           
           }


    }

function TGSLogProcess
    {
        param([String]$ShareName, $FileName)

        ## Event-Id 4769
        $LogTimeSearchPTT1 = (Get-Date).addMinutes(-15) 
        $kerbSecEvent = Get-EventLog -LogName Security -InstanceId 4769 -After $LogTimeSearchPTT1
        FileCheckEvent $ShareName $FileName
        For ($i=3; $i -le 18; $i++)
            {
                $splitEdInf = $kerbSecEvent | % {$_.Message.Split("`n")[$i].Split()[4]}
                #Account Name Inf
                if ($i -eq 3)
                    {
                        $tgsaccountName = $splitEdInf
                    }
                # Account Domain Inf.
                if ($i -eq 4)
                    {
                        $tgsaccoundomain = $splitEdInf
                    }
                # LogonID Inf.
                if ($i -eq 5)
                    {
                        $tgslogonguid = $splitEdInf
                    }
                # Service Inf.
                if ($i -eq 8)
                    {
                        $tgsServiceName = $splitEdInf
                    }
                # Client Address Inf.
                if ($i -eq 12)
                    {
                        $tgsClientAddr = $splitEdInf
                    }
                # Client Port Inf.
                if ($i -eq 13)
                    {
                        $tgsClientPort  = $splitEdInf
                    }
                # Tgs Ticket Operation Inf.
                if ($i -eq 16)
                    {
                        $tgsticketOpt = $splitEdInf
                    }
                # Tgs Encryption Type Inf.
                if ($i -eq 17)
                    {
                        $tgsEncType = $splitEdInf
                    }
                # Tgs Failure Code Inf.
                if ($i -eq 18)
                    {
                        $tgsFailureCode = $splitEdInf
                    }
            }

          # Create Sha256 Hash
          $TimeStampVal = (Get-Date).ToString("yyyy-MM-dd-hh-mm")
          $TimeStampHash = $TimeStampVal + '_EventTGSLog' 
          $SHA256hash = CreateHashSha $TimeStampHash

          #Call
          TGSLogProcessExport $kerbSecEvent $tgsaccountName $tgsaccoundomain $tgslogonguid $tgsServiceName $tgsClientAddr $tgsClientPort $tgsticketOpt $tgsEncType $tgsFailureCode $SHA256hash $TimeStampVal $ShareName $FileName

    }

function TGSLogProcessExport
    {
        param($EventLength, $tgsaccountName, $tgsaccoundomain, $tgslogonguid, $tgsServiceName, $tgsClientAddr, $tgsClientPort, $tgsticketOpt, $tgsEncType, $tgsFailureCode, $SHA256hash, $TimeStampVal, $ShareName, $FileName)
        # list of Arguments
        [System.Collections.ArrayList]$ListOfTgS = @($tgsaccountName, $tgsaccoundomain, $tgslogonguid, $tgsServiceName, $tgsClientAddr, $tgsClientPort, $tgsticketOpt, $tgsEncType, $tgsFailureCode,$SHA256hash, $TimeStampVal)
        $EventMTGS = @()
        #Default TgS Event Types
        [System.Collections.ArrayList]$EventTgSType = @(
            "AccountName",
            "AccountDomain",
            "LogonID",
            "ServiceName",
            "ClientAddress",
            "ClientPort",
            "TicketOperation",
            "EncryptionType",
            "FailureCode",
            "HashValue",
            "TimeStamp"
        )
        # Remove Null Item
        For ($lenS=0; $lenS -lt $ListOfTgS.Count; $lenS++)
            {
                if ($ListOfTgS[$lenS].Length -eq 0)
                    {
                        $EventMTGS += $EventTgSType[$lenS]
                        $EventTgSType.RemoveAt($lenS)
                        $ListOfTgS.RemoveAt($lenS)
                        $lenS--
                    }
            }

        ## Check value
        if ($EventMTGS -ne $null)
            {
                $computerName = $env:COMPUTERNAME
                $msgOfEvent = 'Event Types is ' + $EventM + ' None'
                EventTypeStatus $msgOfEvent $computerName 
            }
        if ($ListOfTgS -eq $null)
            {
                $computerName = $env:COMPUTERNAME
                $msgOfEvent = 'All Event is None '
                EventTypeStatus $msgOfEvent $computerName 
                ## Finish
            }

        if ($ListOfTgS -ne $null)
            {
                ## Adding Update
                $resultTgS = @()
                For ($lenST=0; $lenST -lt $ListOfTgS.Count; $lenST++)
                    {
                        $EventTgSres += @{$EventTgSType[$lenST] = ($ListOfTgS[$lenST] -join ',')}
                        $resultTgS =  New-Object PSObject -Property $EventTgSres

                    }
                try
                    {
                        $resultTgS | Export-Csv -Path $ShareName\$FileName -NoTypeInformation -Force
                        ##Call Storage Export Process and File Create
                        Write-Output $SHA256hash
                        
                    }

                catch
                    {
                        # Call Error 
                        $noExportWork = 'NotWork'
                        notExportToCsv $noExportWork 'Not Export To TgS values'
                    }


                # Export Timestamp and SHA Hash
                Sha256CsvExport $TimeStampVal $SHA256hash $ShareName
            }
        
        
        
    }

function FileCheckEvent
    {
        param([String]$ShareName, [String]$FileName)
         # Check file Name on Path
        $checkexistFile = Test-Path $ShareName\$FileName -PathType Leaf
        if ($checkexistFile -eq $false)
            {
                New-Item -Path $ShareName\ -Name $FileName -ItemType "file" -Value "This is Log File"
            }

    }

