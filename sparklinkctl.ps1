[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$SparkLinkArguments
)

$ErrorActionPreference = 'Stop'
$sparkRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$sparkPython = Get-Command python -ErrorAction SilentlyContinue
if ($null -eq $sparkPython) {
    Write-Error 'Python 3.12 or newer is required for local SNI scanning.'
    exit 1
}

& $sparkPython.Source -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)'
if ($LASTEXITCODE -ne 0) {
    Write-Error 'The python command must provide Python 3.12 or newer.'
    exit 1
}

$env:PYTHONPATH = Join-Path $sparkRoot 'src'
& $sparkPython.Source -m sparklink_deployer.cli @SparkLinkArguments
exit $LASTEXITCODE
