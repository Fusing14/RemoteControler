@echo off
setlocal EnableExtensions
set "NoDefaultCurrentDirectoryInExePath=1"
cd /d "%~dp0"

:: Autodeteccion de carpetas anidadas tras descompresion de ZIP (RemoteControler\RemoteControler)
if not exist "host\main.py" (
    if exist "RemoteControler\host\main.py" (
        cd /d "%~dp0RemoteControler"
    ) else if exist "RemoteControler-main\host\main.py" (
        cd /d "%~dp0RemoteControler-main"
    )
)

if not exist "logs" mkdir "logs"

:: Comprobar si se ejecuta con permisos de Administrador
"%SystemRoot%\System32\net.exe" session >nul 2>&1
if %errorlevel% neq 0 (
    echo [SecureDeck] Solicitando permisos de Administrador para desbloqueo total Winlogon y gestion de energia...
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%SystemRoot%\System32\cmd.exe' -ArgumentList '/c \"\"%~f0\" %*\"' -WorkingDirectory '%CD%' -Verb RunAs"
    exit /b
)

:: Seleccionar interprete de Python (.venv, venv o instalacion del sistema)
set "PYTHON_EXE=python"
if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else if exist "venv\Scripts\python.exe" (
    set "PYTHON_EXE=venv\Scripts\python.exe"
)

"%PYTHON_EXE%" -m host.main gui %* 2>> "logs\startup_error.log"
set "EXIT_CODE=%errorlevel%"

if %EXIT_CODE% neq 0 (
    echo [%DATE% %TIME%] SecureDeck Host finalizo con codigo de error %EXIT_CODE% >> "logs\startup_error.log"
    echo.
    echo [ERROR] SecureDeck Host no pudo iniciarse correctamente (Codigo: %EXIT_CODE%).
    echo Revisa el archivo de diagnostico en: "%CD%\logs\startup_error.log"
    echo Si faltan dependencias, ejecuta: install_host.ps1
    if not "%~1"=="--minimized" pause
)
exit /b %EXIT_CODE%
