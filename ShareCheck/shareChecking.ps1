<#
    Share Folder Check On system 
    ---- Windows Share Folder Privilege -----
    NTFS and share permissions are both often used in Microsoft Windows environments , While share and NTFS permissions both
    serve the same purpose -- preveting unauthorized access -- there are important differences to understand before you 
    determine how to best perform a task like sharing a folder .
    
    ------ NTFS Permissions --------
    
     Full Control -- Users can add, modify , move and delete files and directories , as well as their associated properties.
     In addition, users can change permissions settings for all files and subdirectories.

     Modify -- Users can view and modify files and file properties 
     Read & Execute -- users can run executable files , includeing scripts.
     Read -- users can view files , file properties and directories.
     Write -- users can write to a file and add files to directories.

    Author : @b3kc4t
#>



## Once Check

function CheckShareFolderOnDCSystem
    {
        # Find Domain Name
        $domainObj = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem
        $domainName = $domainObj.Domain
        $computerName = $env:computername
        
        
        ## Find dclog Share
        $ShareFold = Get-WmiObject -class Win32_Share -ComputerName ($computerName + '.' + $domainName)
        if ($ShareFold.Name -eq 'dcLog')
            {
                return 'FOUNDDCLOG'
            }

    
    }

function CheckShareOnDC
    {
        $CheckFold = CheckShareFolderOnDCSystem
        
        if ($CheckFold -eq 'FOUNDDCLOG')
            {
                
                $OutputShare = @()
                $Folder = "\\$env:COMPUTERNAME\dcLog"
                #$Acl = Get-Acl -Path $Folder
                
                
                # Find Session User 
                $FindSessionUser = Get-WMIObject -class Win32_ComputerSystem | select username
                if ($CheckFold -eq 'FOUNDDCLOG')
                    {
                        return $Folder
                    }  
                   
                
            }
    }
 
 function CheckShareFolderOnServerSystem
    {
        # Find Domain Name
        $domainObj = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem
        $domainName = $domainObj.Domain
        $computerName = $env:COMPUTERNAME

        ## Find Server Share
        $ShareFold = Get-WmiObject -class Win32_Share -ComputerName ($computerName + '.' + $domainName)
        if ($ShareFold.Name -eq 'serverLog')
            {
                return 'FOUNDSERVERLOG'
            }
    }


function CheckShareOnServer
    {
        $CheckFold = CheckShareFolderOnServerSystem
        # Note: Session User Permission will add later
        if ($CheckFold -eq 'FOUNDSERVERLOG')
            {
                $OutputShare = @()
                $Folder = "\\$env:COMPUTERNAME\serverLog"
                return $Folder

            }
    }

function CheckShareFolderOnWorkstationSystem
    {
        # Find Domain Name
        $domainObj = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem
        $domainName = $domainObj.Domain
        $computerName = $env:COMPUTERNAME

        ## Find Server Share
        $ShareFold = Get-WmiObject -class Win32_Share -ComputerName ($computerName + '.' + $domainName)
        if ($ShareFold.Name -eq 'workstationLog')
            {
                return 'FOUNDWORKSTATIONLOG'
            }

    }

function ChackShareOnWorkstation
    {
        $CheckFold = CheckShareFolderOnWorkstationSystem
        # Note : Session User Permission will add later
        if($CheckFold -eq 'FOUNDWORKSTATIONLOG')
            {
                $OutputShare = @()
                $Folder = "\\$env:COMPUTERNAME\workstationLog"
                return $FOlder
            }
    }