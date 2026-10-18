# Script de instalacion y configuracion inicial de SecureDeck Host para Windows 11
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "    Instalacion y Configuracion de SecureDeck Host        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Instalar dependencias Python
Write-Host "`n[1/3] Instalando dependencias de Python..." -ForegroundColor Yellow
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 2. Crear acceso directo en el Escritorio
Write-Host "`n[2/3] Creando acceso directo en el Escritorio..." -ForegroundColor Yellow
$desktop = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktop "SecureDeck Host.lnk"
$batPath = Join-Path $PSScriptRoot "Iniciar_SecureDeck.bat"

$ws = New-Object -ComObject WScript.Shell
$shortcut = $ws.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $batPath
$shortcut.WorkingDirectory = $PSScriptRoot
$shortcut.Description = "SecureDeck Host - Control Remoto Seguro para Windows 11"
$shortcut.Save()

Write-Host "  -> Acceso directo creado en: $shortcutPath" -ForegroundColor Green

# 3. Verificacion final
Write-Host "`n[3/3] Verificacion de instalacion..." -ForegroundColor Yellow
python -c "import psutil, cv2, sounddevice, qrcode, uvicorn; print('  -> Modulos verificados correctamente')"

Write-Host "`n[EXITO] SecureDeck Host configurado y listo para usar." -ForegroundColor Green
Write-Host "Puedes ejecutarlo haciendo doble clic en 'SecureDeck Host.lnk' en tu Escritorio." -ForegroundColor Cyan
