$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path "$PSScriptRoot\..\.."
$Requirements = Join-Path $ProjectRoot "requirements.txt"
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

Write-Host "Installing PhishGuard-AI backend and visual module dependencies..."

if (Test-Path $VenvPython) {
    & $VenvPython -m pip install --upgrade pip
    & $VenvPython -m pip install -r $Requirements
}
elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python -m venv (Join-Path $ProjectRoot ".venv")
    & $VenvPython -m pip install --upgrade pip
    & $VenvPython -m pip install -r $Requirements
}
elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 -m venv (Join-Path $ProjectRoot ".venv")
    & $VenvPython -m pip install --upgrade pip
    & $VenvPython -m pip install -r $Requirements
}
else {
    throw "Python was not found. Install Python 3.11+ and tick 'Add python.exe to PATH'."
}

Write-Host "Done."
