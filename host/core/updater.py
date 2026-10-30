"""
Actualizador resiliente y seguro (Zero-Trust Updater) para el servidor Host.
Resuelve definitivamente el fallo 'Command [git, rev-parse, ...] returned non-zero exit status 128'
cuando el proyecto fue descargado como ZIP sin carpeta '.git', e implementa:
1. Auto-reparación de repositorio Git (git init + remote add + fetch + sincronización limpia).
2. Fallback automático por descarga HTTPS de archivo ZIP desde GitHub cuando Git no está instalado.
3. Protección estricta contra Zip Slip / Path Traversal (CWE-22) mediante os.path.commonpath.
4. Validación estricta de TLS y dominio permitido github.com (CWE-494).
5. Copia de seguridad previa de configuración antes de sobrescribir archivos.
"""

import logging
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from host.core.security.path_security import resolve_safe_external_binary

logger = logging.getLogger("RemoteControler.Updater")

DEFAULT_REPO_URL = "https://github.com/marcosat03/RemoteControler.git"
DEFAULT_ZIP_URL = "https://github.com/marcosat03/RemoteControler/archive/refs/heads/main.zip"
ALLOWED_UPDATE_HOSTS = frozenset({
    "github.com",
    "codeload.github.com",
    "api.github.com",
    "objects.githubusercontent.com",
})

# Directorios y archivos locales que jamás deben ser eliminados durante una actualización por ZIP
PRESERVED_LOCAL_NAMES = frozenset({
    ".git",
    ".venv",
    "venv",
    "logs",
    "__pycache__",
    ".pytest_cache",
    "host_config.json",
    "trusted_devices.json",
    "unlock_pin.dat",
})


class UpdateSecurityError(Exception):
    """Excepción ante violación de seguridad en el proceso de actualización (Zip Slip o URL insegura)."""
    pass


class UpdateExecutionError(Exception):
    """Excepción cuando falla la actualización tanto por Git como por ZIP HTTPS."""
    pass


def validate_https_github_url(url: str) -> str:
    """
    Valida que una URL de actualización utilice exclusivamente esquema HTTPS
    y apunte a un host oficial de GitHub (mitigación CWE-494).
    """
    if not url or not isinstance(url, str):
        raise UpdateSecurityError("La URL de actualización no puede estar vacía.")
    cleaned = url.strip()
    parsed = urllib.parse.urlparse(cleaned)
    if parsed.scheme.lower() != "https":
        raise UpdateSecurityError(f"Se requiere HTTPS obligatorio para actualizaciones (recibido '{parsed.scheme}').")
    hostname = (parsed.hostname or "").lower()
    if hostname not in ALLOWED_UPDATE_HOSTS:
        raise UpdateSecurityError(f"Dominio de actualización no autorizado: '{hostname}'.")
    return cleaned


def extract_zip_safely(zip_path: Path, target_dir: Path) -> List[Path]:
    """
    Extrae un archivo ZIP en target_dir verificando que cada miembro resuelva
    estrictamente dentro del directorio destino mediante os.path.commonpath.
    Mitiga explícitamente ataques de Zip Slip / Path Traversal (CWE-22).
    """
    target_root = target_dir.resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    target_root_str = str(target_root)

    extracted_files: List[Path] = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        # Fase 1: Auditar todos los miembros antes de extraer un solo byte
        for member in zf.infolist():
            raw_name = member.filename
            if not raw_name:
                continue

            # Rechazar rutas absolutas o unidades de Windows (C:\, \\server\share)
            if raw_name.startswith(("/", "\\")) or ":" in raw_name:
                raise UpdateSecurityError(f"Zip Slip detectado (ruta absoluta en archivo ZIP): {raw_name}")

            # Normalizar separadores y comprobar segmentos '..'
            norm_parts = Path(raw_name.replace("\\", "/")).parts
            if ".." in norm_parts:
                raise UpdateSecurityError(f"Zip Slip detectado (secuencia '..' en archivo ZIP): {raw_name}")

            dest_path = (target_root / raw_name).resolve()
            dest_str = str(dest_path)

            try:
                common = os.path.commonpath([target_root_str, dest_str])
            except ValueError as ve:
                raise UpdateSecurityError(f"Zip Slip detectado (unidad distinta): {raw_name}") from ve

            if os.path.normcase(common) != os.path.normcase(target_root_str):
                raise UpdateSecurityError(f"Zip Slip detectado (fuera del directorio raíz): {raw_name}")

        # Fase 2: Extracción controlada archivo por archivo (sin usar zf.extractall directo)
        for member in zf.infolist():
            raw_name = member.filename
            if not raw_name:
                continue
            dest_path = (target_root / raw_name).resolve()
            if member.is_dir() or raw_name.endswith(("/", "\\")):
                dest_path.mkdir(parents=True, exist_ok=True)
            else:
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member, "r") as src_f, open(dest_path, "wb") as dst_f:
                    shutil.copyfileobj(src_f, dst_f, length=65536)
                extracted_files.append(dest_path)

    return extracted_files


def create_config_backup(repo_root: Path) -> Optional[Path]:
    """
    Crea una copia de seguridad preventiva de archivos de configuración locales
    antes de aplicar una actualización del servidor.
    """
    try:
        backup_dir = repo_root / "logs" / "backup_pre_update"
        backup_dir.mkdir(parents=True, exist_ok=True)
        for rel_file in ("Iniciar_SecureDeck.bat", "install_host.ps1", "host/requirements.txt"):
            src = repo_root / rel_file
            if src.exists() and src.is_file():
                dst = backup_dir / Path(rel_file).name
                shutil.copy2(src, dst)
        return backup_dir
    except Exception as e:
        logger.debug("No se pudo crear backup preventivo en logs/backup_pre_update: %s", e)
        return None


def _find_git_executable() -> Optional[str]:
    """Localiza git.exe de forma segura sin permitir secuestro desde el directorio actual."""
    try:
        return resolve_safe_external_binary("git.exe" if sys.platform == "win32" else "git")
    except FileNotFoundError:
        return None


def repair_and_update_git_repo(
    repo_root: Path,
    repo_url: str = DEFAULT_REPO_URL,
    branch: str = "main",
    progress_callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    Actualiza el repositorio mediante Git.
    Si el directorio no tiene '.git' (causando el clásico 'exit status 128'),
    inicializa automáticamente el repositorio Git, vincula el remoto oficial HTTPS
    y sincroniza la rama principal conservando los archivos de configuración del usuario.
    """
    validated_url = validate_https_github_url(repo_url)
    git_bin = _find_git_executable()
    if not git_bin:
        raise FileNotFoundError("Git no está instalado en el sistema.")

    repo_root = repo_root.resolve()
    if progress_callback:
        progress_callback("Verificando estado del repositorio Git...")

    # Comprobar si ya es un repositorio Git válido
    is_valid_git = False
    if (repo_root / ".git").exists():
        chk = subprocess.run(
            [git_bin, "rev-parse", "--is-inside-work-tree"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=10,
        )
        is_valid_git = (chk.returncode == 0 and chk.stdout.strip().lower() == "true")

    if not is_valid_git:
        logger.info("Directorio sin '.git' válido detectado (Error 128 prevenido). Auto-reparando repositorio Git...")
        if progress_callback:
            progress_callback("Reparando repositorio Git local (auto-init)...")

        subprocess.run([git_bin, "init"], cwd=str(repo_root), check=True, capture_output=True, text=True, timeout=15)
        subprocess.run([git_bin, "remote", "remove", "origin"], cwd=str(repo_root), capture_output=True, text=True, timeout=10)
        subprocess.run([git_bin, "remote", "add", "origin", validated_url], cwd=str(repo_root), check=True, capture_output=True, text=True, timeout=10)

        if progress_callback:
            progress_callback("Descargando última versión desde GitHub...")
        fetch_res = subprocess.run(
            [git_bin, "fetch", "origin", branch, "--depth=1"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if fetch_res.returncode != 0:
            raise UpdateExecutionError(f"No se pudo conectar con GitHub via Git: {fetch_res.stderr.strip()}")

        # Sincronizar árbol de trabajo con origin/main sin borrar archivos no rastreados (vault/logs/.venv)
        reset_res = subprocess.run(
            [git_bin, "reset", "--hard", f"origin/{branch}"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if reset_res.returncode != 0:
            raise UpdateExecutionError(f"Error al aplicar sincronización Git: {reset_res.stderr.strip()}")

        subprocess.run([git_bin, "branch", "-M", branch], cwd=str(repo_root), capture_output=True, text=True, timeout=10)
        return {
            "method": "git_repaired",
            "updated": True,
            "message": "Repositorio Git reparado y actualizado a la última versión.",
        }

    # Caso normal: el repositorio ya tiene .git válido
    if progress_callback:
        progress_callback("Comprobando actualizaciones en GitHub...")

    fetch_res = subprocess.run(
        [git_bin, "fetch", "origin", branch],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=45,
    )
    if fetch_res.returncode != 0:
        raise UpdateExecutionError(f"Error al consultar origin/{branch}: {fetch_res.stderr.strip()}")

    local_hash = subprocess.run(
        [git_bin, "rev-parse", "HEAD"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()

    remote_hash = subprocess.run(
        [git_bin, "rev-parse", f"origin/{branch}"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()

    if local_hash and remote_hash and local_hash == remote_hash:
        return {
            "method": "git",
            "updated": False,
            "commit": local_hash[:7],
            "message": f"Ya tienes la última versión instalada ({local_hash[:7]}).",
        }

    if progress_callback:
        progress_callback("Descargando cambios desde GitHub...")

    pull_res = subprocess.run(
        [git_bin, "pull", "--rebase", "--autostash", "origin", branch],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=60,
    )
    if pull_res.returncode != 0:
        # Abortar rebase si quedó a medias y sincronizar con origin/branch
        subprocess.run([git_bin, "rebase", "--abort"], cwd=str(repo_root), capture_output=True, timeout=10)
        reset_res = subprocess.run(
            [git_bin, "reset", "--hard", f"origin/{branch}"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if reset_res.returncode != 0:
            raise UpdateExecutionError(f"Error aplicando cambios Git: {pull_res.stderr.strip()}")

    return {
        "method": "git",
        "updated": True,
        "commit": remote_hash[:7] if remote_hash else "",
        "message": f"Servidor actualizado exitosamente a la versión {remote_hash[:7] if remote_hash else 'latest'}.",
    }


def update_via_https_zip(
    repo_root: Path,
    zip_url: str = DEFAULT_ZIP_URL,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    Descarga el paquete ZIP oficial desde GitHub mediante HTTPS con validación estricta TLS,
    verifica la ausencia de Zip Slip (CWE-22) y actualiza los archivos del proyecto
    preservando configuraciones locales y entornos virtuales.
    """
    validated_url = validate_https_github_url(zip_url)
    repo_root = repo_root.resolve()

    if progress_callback:
        progress_callback("Descargando paquete ZIP seguro desde GitHub (HTTPS)...")

    ssl_ctx = ssl.create_default_context()
    req = urllib.request.Request(
        validated_url,
        headers={"User-Agent": "SecureDeck-ZeroTrust-Updater/2.0"},
    )

    with tempfile.TemporaryDirectory(prefix="securedeck_update_") as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        zip_file_path = tmp_dir / "update_bundle.zip"
        extract_dir = tmp_dir / "extracted"

        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=45) as resp, open(zip_file_path, "wb") as out_f:
                # Limitar descarga máxima a 100 MB contra DoS
                max_bytes = 100 * 1024 * 1024
                downloaded = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > max_bytes:
                        raise UpdateSecurityError("El archivo ZIP descargado excede el tamaño máximo de seguridad (100 MB).")
                    out_f.write(chunk)
        except UpdateSecurityError:
            raise
        except Exception as e:
            raise UpdateExecutionError(f"Fallo al descargar actualización HTTPS desde GitHub: {e}") from e

        if progress_callback:
            progress_callback("Verificando integridad anti-Zip-Slip y extrayendo archivos...")

        extract_zip_safely(zip_file_path, extract_dir)

        # GitHub empaqueta el repositorio dentro de una subcarpeta raíz (ej. RemoteControler-main/)
        subdirs = [p for p in extract_dir.iterdir() if p.is_dir()]
        source_root = subdirs[0] if len(subdirs) == 1 else extract_dir

        if progress_callback:
            progress_callback("Aplicando archivos actualizados conservando configuración...")

        files_copied = 0
        for src_item in source_root.rglob("*"):
            rel_path = src_item.relative_to(source_root)
            if not rel_path.parts:
                continue
            if rel_path.parts[0] in PRESERVED_LOCAL_NAMES or src_item.name in PRESERVED_LOCAL_NAMES:
                continue

            dest_item = (repo_root / rel_path).resolve()
            # Validación adicional de confinamiento en repo_root
            if os.path.normcase(os.path.commonpath([str(repo_root), str(dest_item)])) != os.path.normcase(str(repo_root)):
                raise UpdateSecurityError(f"Intento de escritura fuera de raíz bloqueado: {rel_path}")

            if src_item.is_dir():
                dest_item.mkdir(parents=True, exist_ok=True)
            elif src_item.is_file():
                dest_item.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_item, dest_item)
                files_copied += 1

    return {
        "method": "https_zip",
        "updated": True,
        "files_updated": files_copied,
        "message": f"Actualización completada vía HTTPS ZIP ({files_copied} archivos sincronizados).",
    }


def perform_resilient_update(
    repo_root: Path,
    repo_url: str = DEFAULT_REPO_URL,
    zip_url: str = DEFAULT_ZIP_URL,
    progress_callback: Optional[Callable[[str], None]] = None,
    install_dependencies: bool = True,
) -> Dict[str, Any]:
    """
    Orquesta el proceso completo de actualización resiliente:
    1. Crea copia de seguridad previa.
    2. Intenta actualizar/reparar vía Git; si Git no está instalado o falla, usa fallback HTTPS ZIP.
    3. Si hubo cambios y install_dependencies=True, actualiza dependencias pip.
    """
    repo_root = repo_root.resolve()
    create_config_backup(repo_root)

    result: Dict[str, Any]
    try:
        result = repair_and_update_git_repo(
            repo_root=repo_root,
            repo_url=repo_url,
            progress_callback=progress_callback,
        )
    except (FileNotFoundError, UpdateExecutionError) as git_err:
        logger.warning("Actualización vía Git no disponible (%s). Activando fallback seguro HTTPS ZIP...", git_err)
        result = update_via_https_zip(
            repo_root=repo_root,
            zip_url=zip_url,
            progress_callback=progress_callback,
        )

    if install_dependencies and result.get("updated"):
        req_file = repo_root / "host" / "requirements.txt"
        if req_file.exists():
            if progress_callback:
                progress_callback("Verificando dependencias de Python (pip)...")
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-r", str(req_file), "--quiet"],
                    cwd=str(repo_root),
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except Exception as pip_err:
                logger.warning("Advertencia al actualizar dependencias pip: %s", pip_err)

    return result
