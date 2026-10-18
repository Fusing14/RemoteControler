@echo off
setlocal
cd /d "%~dp0"

:: Comprobar si se ejecuta con permisos de Administrador
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [SecureDeck] Solicitando permisos de Administrador para desbloqueo total Winlogon y gestion de procesos...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c \"\"%~dpnx0\" %*\"' -Verb RunAs"
    exit /b
)

:: Con permisos de Administrador, ejecutar RemoteControler Host GUI
if exist "venv\Scripts\python.exe" (
    "venv\Scripts\python.exe" -m host.main gui %*
) else (
    python -m host.main gui %*
)
exit /b
