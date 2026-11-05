# Qwen 3.8 analysis after the Cohere report. Nothing starts until you run this file, and it needs a model server you start yourself.
# Usage: .\run-analysis.ps1 fetch | first | follow | tokens | report | all   [options of run.py, e.g. --url http://127.0.0.1:7232 --n 50]
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if (-not $py) { throw "Python 3.10 or later was not found in PATH" }
if ($args.Count -lt 1) {
    Write-Host "usage: .\run-analysis.ps1 fetch|first|follow|tokens|report|all [run.py options]"
    Write-Host "       python $here\run.py --help   for the options"
    exit 2
}
& $py.Source (Join-Path $here "run.py") @args
exit $LASTEXITCODE
