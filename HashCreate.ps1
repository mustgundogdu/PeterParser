
# The SHA-256 generates an almost-unique 256-bit (32-byte) signature for a text. See below for the source code.

function CreateHashSha

     {
        param([String]$PlainText)
        $Hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
        $hash = $Hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($PlainText))
        # Encryption with Sha256
        $HashText = [System.BitConverter]::ToString($hash)
        $EncryptToHash = $HashText.Replace('-','')
        
        return $EncryptToHash
     } 


function CreateHashSha512
    {
        param([String]$PlainText)
        $Hasher512 = [System.Security.Cryptography.HashAlgorithm]::Create('sha512')
        $hash512 = $Hasher512.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($PlainText))
        # Encryption with SHA512
        $HashText = [System.BitConverter]::ToString($hash512)
        $EncryptHash = $HashText.Replace('-','')

        return $EncryptHash
    }
