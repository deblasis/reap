# The reap gate (round 11; the R8/R9 eng seat: "the gate for a destructive,
# CI-less tool must not be skippable by construction"). Every step runs; ANY
# failure fails the script. No &&-chaining, no short-circuit.
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot
$failed = $false

Write-Host "== gofmt (must be clean) =="
$dirty = & gofmt -l .
if ($dirty) { $dirty | ForEach-Object { Write-Host "UNFORMATTED: $_" }; $failed = $true }

Write-Host "== go vet =="
& go vet ./...
if ($LASTEXITCODE -ne 0) { $failed = $true }

Write-Host "== go test (serialized) =="
& go test -p 1 ./... -count=1 -timeout 40m
if ($LASTEXITCODE -ne 0) { $failed = $true }

if ($failed) { Write-Host "GATE: FAILED"; exit 1 }
Write-Host "GATE: GREEN"
