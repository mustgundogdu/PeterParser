# Log File Import
. ".\LogF\LogToScr.ps1"

function ReturnSessionsTGTs 
    {
        param([string]$ShareName, [string]$FileName)
        $InfTick = 'TGTicket.csv'
        # Current Session Import
        $csvFile = Import-Csv $ShareName\$FileName

        ## Checking File Exist 
        FileProcess $InfTick $ShareName
        # Create Title on Export TGT ticket File
        "ClientName, SessionID" | Out-File $ShareName\$InfTick

        foreach($UserHex in $csvFile.SessionId)
            {
                # Cached tickets with sessionId
                $RawTGT = klist.exe -li $UserHex

                if ($RawTGT -contains 'Error calling API LsaCallAuthenticationPackage (Ticket Granting Ticket substatus): 1312')
                    {
                        $TGT = 'Not Ticketgrantingticket cached in session'
                        # write Log File
                        TicketStaus $TGT $UserHex
                    }

                elseif ($RawTGT -contains 'Cached Tickets: (0)')
                    {
                        $TGT = 'No Tickets'
                        # Write Log File
                        TicketStaus $TGT $UserHex
                    }

                else
                    {
                        # Split cached Tickets
                        foreach($i in $RawTGT)
                            {
                                $TGT = $i.split('#')[1]
                                if ($TGT -eq $null)
                                    {
                                        $TGT = 'TGT is Null'
                                        # Write Log File
                                        TicketStaus $TGT $UserHex
                                    }

                                else
                                    {
                                        # Check Write File
                                        try
                                            { 
                                                "$($TGT), $($UserHex)" | Out-File $ShareName\$InfTick -Append
                                            }
                                        catch 
                                            {
                                                "' ', ' '" | Out-File $ShareName\$InfTick -Append
                                            }


                                    }
                                
                            }
                    
                    }
                
            }
    }


    function FileProcess
        {
            param ($fileName1, $ShareName)
            # check Exist Files
            $checkexistfile = Test-Path $ShareName\$fileName1 -PathType Leaf

            ##
            if ($checkexistfile -eq $false)
                {
                    # Create File
                    New-Item -Path "$ShareName\" -Name $fileName1 -ItemType "file"
                }
            
        
        }