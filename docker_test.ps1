$pwd = (Get-Location).Path
$memdumpsPath = "$pwd\memdumps"
$outputPath = "$pwd\output"

# Convert to Windows path with proper escaping
$memdumpsPath = ($memdumpsPath -replace '/', '\')
$outputPath = ($outputPath -replace '/', '\')

docker run --rm -it `
  -v "$memdumpsPath":/memdumps `
  -v "$outputPath":/output `
  autovol python autovol.py -h