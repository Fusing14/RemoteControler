# Script de instalacion y configuracion inicial de SecureDeck Host para Windows 11
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "    Instalacion y Configuracion de SecureDeck Host        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Verificacion previa de Python en PATH
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "`n[ERROR] Python no esta disponible en el PATH del sistema." -ForegroundColor Red
    Write-Host "Por favor instala Python 3.12 o superior asegurandote de marcar 'Add python.exe to PATH'." -ForegroundColor Yellow
    exit 1
}

# 1. Instalar dependencias Python
Write-Host "`n[1/3] Instalando dependencias de Python..." -ForegroundColor Yellow
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 2. Crear acceso directo en el Escritorio y configurar reglas de red
Write-Host "`n[2/3] Creando acceso directo en el Escritorio y reglas de red..." -ForegroundColor Yellow
$desktop = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktop "SecureDeck Host.lnk"
$batPath = Join-Path $PSScriptRoot "Iniciar_SecureDeck.bat"

if (Test-Path $batPath) {
    $ws = New-Object -ComObject WScript.Shell
    $shortcut = $ws.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $batPath
    $shortcut.WorkingDirectory = $PSScriptRoot
    $shortcut.IconLocation = "shell32.dll,15"
    $shortcut.Description = "SecureDeck Host - Control Remoto Seguro para Windows 11"
    $shortcut.Save()
    Write-Host "  -> Acceso directo creado en: $shortcutPath" -ForegroundColor Green
} else {
    Write-Host "  -> [ADVERTENCIA] No se encontro '$batPath'. No se pudo crear el acceso directo." -ForegroundColor Yellow
}

# Regla del Firewall de Windows (silenciosa si no cuenta con privilegios de Administrador)
try {
    if (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue) {
        $existing = Get-NetFirewallRule -DisplayName "SecureDeck Host Server" -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule -DisplayName "SecureDeck Host Server" `
                -Direction Inbound `
                -Protocol TCP `
                -LocalPort 8443, 8000 `
                -Action Allow `
                -Description "Permite la conexion entrante del cliente movil SecureDeck" `
                -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  -> Regla de Firewall de Windows configurada (puertos 8443, 8000 TCP)." -ForegroundColor Green
        }
    }
} catch {
    # Silencioso si no cuenta con privilegios de Administrador
}

# 3. Verificacion final
Write-Host "`n[3/3] Verificacion de instalacion..." -ForegroundColor Yellow
python -c "import psutil, cv2, mss, cryptography, fastapi, qrcode, uvicorn; print('  -> Modulos verificados correctamente')"

Write-Host "`n[EXITO] SecureDeck Host configurado y listo para usar." -ForegroundColor Green
Write-Host "Puedes ejecutarlo haciendo doble clic en 'SecureDeck Host.lnk' en tu Escritorio." -ForegroundColor Cyan
