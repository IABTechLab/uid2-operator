function Test  {
    param 
    (
        [string] $a, 
        [ref] $b
    )

    Write-Host $a
    gcloud iam service-accounts create qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
    if ($LASTEXITCODE -ne 0){ Throw "Error creating service account" }

    $b.Value = "world"
}

$ErrorActionPreference = 'Stop'

$c = ""
Test -a "hello" -b ([ref]$c)

Write-Host $c