# SHA256

function CreateHash
     {
        param([String]$PlainText)
        $Hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
        $hash = $Hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($PlainText))

        $HashText = [System.BitConverter]::ToString($hash)
        Write-Output $HashText.Replace('-','')
        #$HashText.Replace('-','')
     } 


    CreateHash "Unsafe-Inline120203"
