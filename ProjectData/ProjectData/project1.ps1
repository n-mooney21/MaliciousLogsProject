# < Advanced Scripting Project >
# < Detector 1: Malicious IPs in the Logs >
$Malicious_IPs = @(
   "198.51.100.8",
   "203.0.113.5"  
)

$File1 = Join-Path $PSScriptRoot "access.log"

Write-Output "Scanning Logs for Known Malicious Threats..."
Write-Output "`n" 


$AllIPs = Get-Content $File1 | 
             Select-String -Pattern '\b\d{1,3}(\.\d{1,3}){3}\b' -AllMatches | 
             ForEach-Object { $_.Matches.Value }

$ipTotal = $AllIPs.Count


$GroupedIPs = $AllIPs | Group-Object | Sort-Object Count -Descending

foreach ($item in $GroupedIPs) {
    if ($Malicious_IPs -contains $item.Name) {

        $RiskLvl = if ($item.Count -gt 100) { "CRITICAL" } 
                     elseif ($item.Count -gt 50) { "HIGH" } 
                     else { "MEDIUM" }
        Write-Output "WARNING!: Malicious IP found: $($item.Name) - Occurence of IP in the Logs: $($item.Count)" 
    }
}
Write-Output "Scan Complete." 
Write-Output "Total Ips Checked: $ipTotal"
Write-Output "Estimated Risk Level: $RiskLvl"
Write-Output "`n"

# < Detector 2: Suspicious Linux Command Executions >

$SuspiciousCMD = @(
    "chmod",      
    "curl",    
    "rm -rf",  
    "sudo",    
    "passwd",  
    "nc",      
    "/tmp"     
)

$File2 = Join-Path $PSScriptRoot "auth.log"

Write-Output "Checking Logs for Suspicious use of Linux Commands..."
Write-Output "`n"

$SPCommands = Get-Content $File2 | Select-String "Command="

$count = 0

foreach ($line in $SPCommands){
    foreach($word in $SuspiciousCMD){
        if ($line -like "*$word*"){

            $Risk = switch ($word) {
                "rm -rf" { "CRITICAL" }
                "nc"     { "CRITICAL" }
                "sudo"   { "MEDIUM" }
                default  { "HIGH" }
            }

            Write-Output "Suspicous Command Spotted in Logs!: $word" 
            Write-Output "Risk Level of Command: $Risk"
            Write-Output "Full Command in Logs: $($line.ToString().Trim())"
            Write-Output "***************************************************************"
            Write-Output "`n"

            $count++
            break
        }
    }
}

Write-Output "Log Scan for Suspicious Commands Completed. Found $count Matches." 
Write-Output "`n"

# < Detector 3: Finding Malicious Web Paths in the Logs >

$webPaths =@(
    "/wp-admin",
    "/phpmyadmin",
    "/admin",
    "/.env",
    "/config.php"
)
         
$File1 = Join-Path $PSScriptRoot "access.log"

Write-Output "Scanning Logs for Malicous Web Paths..."
Write-Output "`n"

$LogScan = Get-Content $File1

$amount = 0

foreach($line in $LogScan){
    foreach($path in $webPaths) {
        if ($line -like "*$path*") {
            $Risk = switch ($path) {
                "/.env"       { "CRITICAL" }
                "/config.php" { "CRITICAL" }
                "/wp-admin"   { "HIGH" }
                default       { "MEDIUM" }
            }

            Write-Output "Malicious Web Path has been detected!: $path" 
            Write-Output "Risk Level: $Risk"
            Write-Output "Full Request: $($line.trim())"
            Write-Output "***************************************************************"
            Write-Output "`n"

            $amount++
            break
        }           
    }
}

Write-Output "Malicious Web Path Scan has been Completed. Found $amount unauthorized access attempts." 