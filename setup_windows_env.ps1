$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Prefer the Python launcher on Windows when available.
if (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonExe = 'py'
    $pythonArgs = @('-3')
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonExe = 'python'
    $pythonArgs = @()
} else {
    throw 'Python was not found. Install Python 3 and ensure "py" or "python" is in PATH.'
}

$venvPath = '.venv_sick_visionary_samples'

& $pythonExe @pythonArgs -m venv $venvPath
& ".\$venvPath\Scripts\Activate.ps1"

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

$activateCmd = '.\.venv_sick_visionary_samples\Scripts\Activate.ps1'

Write-Host 'Setup completed.' -ForegroundColor Green
Write-Host ''
Write-Host '============================================================' -ForegroundColor Yellow
Write-Host '  ACTIVATE ENVIRONMENT WITH:' -ForegroundColor Yellow
Write-Host "  $activateCmd" -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Yellow
Write-Host ''
