$ErrorActionPreference = "Stop"
$installer = Split-Path -Parent $MyInvocation.MyCommand.Path
$project = Split-Path -Parent $installer
Set-Location -LiteralPath $project

python -m pip install --disable-pip-version-check -r `
    (Join-Path $installer "build-requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "Build-Abhängigkeiten konnten nicht installiert werden." }

python -m PyInstaller --noconfirm --clean `
    --distpath (Join-Path $installer "dist") `
    --workpath (Join-Path $installer "build") `
    (Join-Path $installer "ir-tracker-installer.spec")
if ($LASTEXITCODE -ne 0) { throw "Windows-EXE konnte nicht gebaut werden." }

Write-Host "Fertig:" (Join-Path $installer "dist\IR-Tracker-Installer.exe")
