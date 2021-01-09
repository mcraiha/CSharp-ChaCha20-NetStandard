DATE=`date -Iseconds`
SHORTHASH=`git rev-parse --short HEAD | xargs`
echo "dotnet pack --configuration Release --include-source --include-symbols /p:InformationalVersion=\"Build time: $DATE Short hash: $SHORTHASH\""