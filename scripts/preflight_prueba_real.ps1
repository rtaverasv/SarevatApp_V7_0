param(
    [string]$Python = ".\.venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Python)) {
    throw "No se encontró Python en '$Python'. Activa o crea el entorno virtual antes de la prueba."
}

& $Python -m pytest -q --cov=sarevat --cov-branch --cov-report=term-missing
& $Python -m ruff check sarevat tests
& $Python -m bandit -q -r sarevat
& $Python -m pip check

if ($LASTEXITCODE -ne 0) {
    throw "La preflight no terminó correctamente. No conectes equipos hasta corregir el resultado."
}

Write-Host "Preflight local aprobada. Falta completar el piloto Cisco y registrar la evidencia." -ForegroundColor Green
