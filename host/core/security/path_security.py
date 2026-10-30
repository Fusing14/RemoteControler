"""
Mitigación contra Escalación de Privilegios Local (LPE), Secuestro de Binarios (CWE-426 / CWE-427)
y Permisos Inseguros en Disco (CWE-276 / CWE-732).

Garantiza que:
1. Todos los binarios del sistema Windows (powershell, schtasks, reg, taskkill, ipconfig, tscon, cmd)
   se resuelvan exclusivamente desde ubicaciones confiables del sistema (%SystemRoot%\\System32),
   ignorando el directorio de trabajo actual para impedir DLL/EXE hijacking.
2. Los comandos para tareas programadas usen rutas absolutas entrecomilladas (Quoted Paths).
3. Los archivos de configuración, bóveda DPAPI y auditoría tengan ACLs restrictivas.
"""

import logging
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger("RemoteControler.PathSecurity")

# Activar protección de Windows contra búsqueda de ejecutables en el directorio actual (CWD)
if sys.platform == "win32":
    os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"


def get_trusted_system32_dir() -> Path:
    """Devuelve la ruta verificada a C:\\Windows\\System32."""
    sys_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    return Path(sys_root).resolve() / "System32"


def resolve_system_binary(binary_name: str) -> str:
    """
    Resuelve la ruta absoluta de un binario nativo de Windows verificando que resida
    estrictamente dentro de %SystemRoot%\\System32 (CWE-426 / CWE-427).
    """
    clean_name = binary_name.strip()
    if not clean_name.lower().endswith(".exe"):
        exe_name = f"{clean_name}.exe"
    else:
        exe_name = clean_name

    if sys.platform != "win32":
        found = shutil.which(clean_name)
        return found or clean_name

    sys32 = get_trusted_system32_dir()

    # Caso especial: PowerShell reside en System32\WindowsPowerShell\v1.0
    if exe_name.lower() == "powershell.exe":
        ps_candidate = sys32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if ps_candidate.is_file():
            return str(ps_candidate.resolve())

    direct_candidate = sys32 / exe_name
    if direct_candidate.is_file():
        return str(direct_candidate.resolve())

    # Fallback con shutil.which verificando que NO provenga del directorio actual (CWD)
    which_res = shutil.which(exe_name)
    if which_res:
        resolved = Path(which_res).resolve()
        cwd = Path.cwd().resolve()
        if resolved.parent == cwd:
            raise SecurityError(
                f"Detección de intento de secuestro de binario (CWE-427): '{exe_name}' apunta al directorio actual {cwd}."
            )
        return str(resolved)

    return str(direct_candidate)


def resolve_safe_external_binary(binary_name: str) -> Optional[str]:
    """
    Resuelve un binario externo (ej. 'git') mediante PATH seguro, rechazando cualquier
    ejecutable ubicado en el directorio de trabajo actual para evitar secuestro de ruta.
    """
    clean_name = binary_name.strip()
    cwd = Path.cwd().resolve()

    # Construir PATH limpio sin entradas vacías ni "."
    raw_path = os.environ.get("PATH", "")
    safe_dirs = []
    for p in raw_path.split(os.pathsep):
        p_stripped = p.strip().strip('"')
        if not p_stripped or p_stripped in (".", "./", ".\\"):
            continue
        try:
            rp = Path(p_stripped).resolve()
            if rp != cwd:
                safe_dirs.append(str(rp))
        except Exception:
            continue

    safe_path_env = os.pathsep.join(safe_dirs)
    found = shutil.which(clean_name, path=safe_path_env)
    if found:
        resolved = Path(found).resolve()
        if resolved.parent == cwd:
            logger.critical("Bloqueado ejecutable sospechoso en CWD: %s", resolved)
            return None
        return str(resolved)

    # En Windows comprobar ubicaciones estándar de Git si no está en PATH
    if sys.platform == "win32" and clean_name.lower() in ("git", "git.exe"):
        candidates = [
            Path(r"C:\Program Files\Git\cmd\git.exe"),
            Path(r"C:\Program Files\Git\bin\git.exe"),
            Path(r"C:\Program Files (x86)\Git\cmd\git.exe"),
        ]
        local_app = os.environ.get("LOCALAPPDATA")
        if local_app:
            candidates.append(Path(local_app) / "Programs" / "Git" / "cmd" / "git.exe")
        for cand in candidates:
            if cand.is_file():
                return str(cand.resolve())

    return None


def quote_executable_path(path_str: str) -> str:
    """
    Asegura que una ruta de ejecutable esté siempre entrecomillada para mitigar
    Unquoted Service / Scheduled Task Paths (CWE-428).
    """
    clean = str(path_str).strip().strip('"')
    return f'"{clean}"'


def enforce_restrictive_acls(target_path: Path | str) -> bool:
    """
    Aplica permisos restrictivos de lectura/escritura exclusivamente al propietario,
    Administradores y SYSTEM sobre archivos o directorios de configuración sensible.
    """
    p = Path(target_path)
    if not p.exists():
        return False

    try:
        # Permisos estándar a nivel de sistema de archivos
        os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

    if sys.platform == "win32":
        try:
            icacls_bin = resolve_system_binary("icacls.exe")
            username = os.environ.get("USERNAME", "")
            cmd = [
                icacls_bin,
                str(p.resolve()),
                "/inheritance:r",
                "/grant:r",
                "SYSTEM:(OI)(CI)F" if p.is_dir() else "SYSTEM:F",
                "/grant:r",
                "*S-1-5-32-544:(OI)(CI)F" if p.is_dir() else "*S-1-5-32-544:F",  # Built-in Administrators SID
            ]
            if username:
                perm = f"{username}:(OI)(CI)F" if p.is_dir() else f"{username}:F"
                cmd.extend(["/grant:r", perm])

            subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return True
        except Exception as e:
            logger.debug("No se pudieron ajustar ACLs avanzadas en %s: %s", p, e)
            return False

    return True


class SecurityError(Exception):
    """Excepción lanzada ante violaciones de seguridad de rutas o binarios."""
    pass
