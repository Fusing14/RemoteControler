# Script de instalacion, blindaje y configuracion integral de SecureDeck Host para Windows 10/11
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# Autodeteccion de carpetas anidadas tras extraccion de ZIP
if (-not (Test-Path (Join-Path $PSScriptRoot "host\main.py"))) {
    if (Test-Path (Join-Path $PSScriptRoot "RemoteControler\host\main.py")) {
        Set-Location (Join-Path $PSScriptRoot "RemoteControler")
    } elseif (Test-Path (Join-Path $PSScriptRoot "RemoteControler-main\host\main.py")) {
        Set-Location (Join-Path $PSScriptRoot "RemoteControler-main")
    }
}

$ProjectRoot = (Get-Location).Path
$LogsDir = Join-Path $ProjectRoot "logs"
if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Instalacion Zero-Trust de SecureDeck Host (Windows)    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Verificacion previa de Python en PATH
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "`n[ERROR] Python no esta disponible en el PATH del sistema." -ForegroundColor Red
    Write-Host "Instala Python 3.11+ asegurandote de marcar 'Add python.exe to PATH'." -ForegroundColor Yellow
    exit 1
}

# 1. Instalar dependencias Python
Write-Host "`n[1/4] Instalando dependencias de Python..." -ForegroundColor Yellow
$ReqPath = Join-Path $ProjectRoot "host\requirements.txt"
if (-not (Test-Path $ReqPath)) {
    $ReqPath = Join-Path $ProjectRoot "requirements.txt"
}
python -m pip install --upgrade pip
python -m pip install -r $ReqPath

# 2. Configurar Wake-on-LAN (Desactivar Fast Startup y activar Magic Packet en adaptadores fisicos)
Write-Host "`n[2/4] Configurando Wake-on-LAN y energia (Cold Boot S5)..." -ForegroundColor Yellow
try {
    python -c "from host.core.network.wol import configure_windows_wol; r = configure_windows_wol(); print('  -> ' + r.get('message', 'OK'))"
} catch {
    Write-Host "  -> [INFO] Ejecuta este script como Administrador para deshabilitar Fast Startup (Hiberboot)." -ForegroundColor Yellow
}

# 3. Crear acceso directo en el Escritorio y configurar reglas de Firewall
Write-Host "`n[3/4] Creando acceso directo en el Escritorio y reglas de Firewall..." -ForegroundColor Yellow
$desktop = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktop "SecureDeck Host.lnk"
$batPath = Join-Path $ProjectRoot "Iniciar_SecureDeck.bat"

if (Test-Path $batPath) {
    $ws = New-Object -ComObject WScript.Shell
    $shortcut = $ws.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $batPath
    $shortcut.WorkingDirectory = $ProjectRoot
    $shortcut.IconLocation = "shell32.dll,15"
    $shortcut.Description = "SecureDeck Host - Control Remoto Zero-Trust para Windows 11"
    $shortcut.Save()
    Write-Host "  -> Acceso directo creado en: $shortcutPath" -ForegroundColor Green
}

try {
    if (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue) {
        $existingTcp = Get-NetFirewallRule -DisplayName "SecureDeck Host Server" -ErrorAction SilentlyContinue
        if (-not $existingTcp) {
            New-NetFirewallRule -DisplayName "SecureDeck Host Server" `
                -Direction Inbound `
                -Protocol TCP `
                -LocalPort 8443, 8000 `
                -Action Allow `
                -Description "Permite la conexion entrante del cliente movil SecureDeck" `
                -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  -> Regla de Firewall TCP (8443, 8000) configurada." -ForegroundColor Green
        }
        $existingUdp = Get-NetFirewallRule -DisplayName "SecureDeck Wake-on-LAN UDP" -ErrorAction SilentlyContinue
        if (-not $existingUdp) {
            New-NetFirewallRule -DisplayName "SecureDeck Wake-on-LAN UDP" `
                -Direction Inbound `
                -Protocol UDP `
                -LocalPort 7, 9, 40000 `
                -Action Allow `
                -Description "Permite paquetes magicos Wake-on-LAN en puertos UDP 7, 9 y 40000" `
                -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  -> Regla de Firewall UDP (7, 9, 40000) configurada para Wake-on-LAN." -ForegroundColor Green
        }
    }
} catch {
    # Silencioso si no se ejecuta como Administrador
}

# 4. Verificacion final
Write-Host "`n[4/4] Verificacion de modulos criticos..." -ForegroundColor Yellow
python -c "import psutil, cv2, mss, cryptography, fastapi, qrcode, uvicorn; print('  -> Modulos verificados correctamente')"

Write-Host "`n[EXITO] SecureDeck Host blindado y listo para usar." -ForegroundColor Green
Write-Host "Haz doble clic en 'SecureDeck Host.lnk' en tu Escritorio para iniciar." -ForegroundColor Cyan
