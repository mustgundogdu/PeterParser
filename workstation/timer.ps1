$delay = 10

while ($delay -ge 0)
    {
        Write-Output "Seconds Remaining: $($delay)"
        Start-Sleep -Seconds 1
        $delay -= 1
        if ($delay%5 -eq 0)
            {
                write-output 'Mod'
            }
        if ($delay -eq 0)
            {
                write-output '1'
                write-output '2'
                $delay = 10
            }
    }
