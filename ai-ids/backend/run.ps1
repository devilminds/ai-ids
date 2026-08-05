# Run this from anywhere: right-click -> Run with PowerShell,
# or in a terminal: .\run.ps1
# It always cd's to its own folder first, so path drift can't happen.

Set-Location -Path $PSScriptRoot
.\venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --port 8000
