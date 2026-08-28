[CmdletBinding()]
param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

Write-Host "Validando SarevatApp: pruebas, estilo, seguridad y dependencias..." -ForegroundColor Cyan
& $Python -m pytest -q --cov=sarevat --cov-branch --cov-report=term-missing
& $Python -m ruff check SarevatApp_V7_0.py sarevat tests
& $Python -m bandit -q -r sarevat SarevatApp_V7_0.py
& $Python -m pip check
Write-Host "Validación local completada." -ForegroundColor Green
