# Starts the MalWeight Canary (Openweight Canary) page. Nothing is started until you run this file.
# Usage: .\run-canary.ps1 [-Config canary.json] [-Port 8765] [-NoBrowser]
param(
    [string]$Config = "canary.json",
    [int]$Port = 8765,
    [switch]$NoBrowser
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($Port -eq 8080) { throw "port 8080 is not allowed; choose another with -Port" }
$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { $py = (Get-Command py -ErrorAction SilentlyContinue) }
if (-not $py) { throw "Python 3.10 or later was not found in PATH" }
$env:PYTHONPATH = $here
Set-Location $here
if (-not (Test-Path $Config)) {
    Write-Host "No $Config yet: writing a starting one."
    & $py.Source -m canary init --dir (Split-Path -Parent (Join-Path $here $Config))
}
$args = @("-m", "canary", "gui", "-c", $Config, "--port", $Port)
if ($NoBrowser) { $args += "--no-browser" }
& $py.Source @args
