# Git command used for getting latest commit
$gitCmdName = "git"
$gitCmdParameter = "rev-parse HEAD"

$currentDate = Get-Date
# Write-Host $currentDate.ToUniversalTime()

$latestGitCommitHashFull = "Git is not installed"
$latestGitCommitHashShort = "Git is not installed"

if (Get-Command $gitCmdName -errorAction SilentlyContinue)
{
	$latestGitCommitHashFull = &git rev-parse HEAD
	$latestGitCommitHashShort = &git rev-parse --short HEAD
    # Write-Host "$gitCmdName exists"
}

Write-Host $latestGitCommitHashFull $latestGitCommitHashShort
$finalCommand = "dotnet pack" + " " + "--configuration Debug" + " " + "--include-source" + " " + "--include-symbols" + " " + "/p:InformationalVersion=""" + $currentDate.ToUniversalTime().ToString("yyyy-MM-dd HH.mm.ss") + " " + $latestGitCommitHashFull + """" + " " + "--version-suffix" + " git-" + $latestGitCommitHashShort
Write-Host $finalCommand