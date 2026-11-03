
$DetectorScript = Join-Path $PSScriptRoot "project1.ps1"
$ReportofScriptsFile = "ProjectReportFile.txt"

Write-Host "Automation of Detectors has been Started... Scanning all logs now." -ForegroundColor Cyan

"******************************************" | Out-File -FilePath $ReportofScriptsFile
"Report File from Detectors"| Out-File -FilePath $ReportofScriptsFile -Append
"******************************************" | Out-File -FilePath $ReportofScriptsFile -Append
"`n"| Out-File -FilePath $ReportofScriptsFile -Append


& $DetectorScript | Out-File -FilePath $ReportofScriptsFile -Append

Write-Host "Automation of Detectors Completed" -ForegroundColor Green
Write-Host "Full results saved to: $ReportofScriptsFile" -ForegroundColor Yellow