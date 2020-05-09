$currentDate = Get-Date
$gitShortHash = ((git rev-parse --short HEAD) | Out-String).Trim()
$finalCommand = "dotnet pack" + " " + "--configuration Release" + " " + "--include-source" + " " + "--include-symbols" + " " + "/p:InformationalVersion=""" + "Build time: " + $currentDate.ToUniversalTime().ToString("yyyy-MM-dd HH.mm.ss") + " Short hash: " + $gitShortHash + """"
Write-Host $finalCommand