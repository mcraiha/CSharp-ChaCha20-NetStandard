$currentDate = Get-Date
$finalCommand = "dotnet pack" + " " + "--configuration Release" + " " + "--include-source" + " " + "--include-symbols" + " " + "/p:InformationalVersion=""" + $currentDate.ToUniversalTime().ToString("yyyy-MM-dd HH.mm.ss") + """"
Write-Host $finalCommand