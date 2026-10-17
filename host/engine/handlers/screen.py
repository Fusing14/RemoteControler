"""
Manejador de captura de pantalla en vivo (Live Screen View).
Captura el monitor primario de forma eficiente y lo devuelve como JPEG comprimido en Base64.
"""

import base64
import io
import logging
import sys
from typing import Dict, Any

logger = logging.getLogger("RemoteControler.ScreenHandler")


class ScreenCaptureError(Exception):
    """Excepción para fallos al capturar el frame de pantalla."""
    pass


def capture_screen_jpeg(max_width: int = 1280, max_height: int = 720, quality: int = 70) -> Dict[str, Any]:
    """
    Captura el monitor principal, lo escala a resolución óptima manteniendo la relación de aspecto,
    y retorna la imagen JPEG en Base64 junto con sus dimensiones.
    """
    img = None

    # 1. Intentar captura de alta velocidad con MSS
    try:
        import mss

        with mss.MSS() as sct:
            # Monitor 1 suele ser el monitor principal; si solo hay 1 entrada, usar monitor 0
            mon = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
            raw = sct.grab(mon)
            from PIL import Image
            img = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
    except Exception as e:
        logger.debug("Captura nativa MSS no disponible: %s. Probando fallback.", e)

    # 2. Fallback con PIL ImageGrab si MSS falló
    if img is None:
        try:
            from PIL import ImageGrab
            img = ImageGrab.grab(all_screens=False)
        except Exception as e:
            logger.debug("ImageGrab fallback falló: %s", e)

    # 3. Fallback de contingencia (pantalla bloqueada o entorno headless en CI/CD)
    if img is None:
        try:
            from PIL import Image, ImageDraw
            img = Image.new("RGB", (max_width, max_height), color=(15, 17, 23))
            draw = ImageDraw.Draw(img)
            text = "Pantalla no disponible / Sesion bloqueada"
            draw.text((max_width // 4, max_height // 2), text, fill=(148, 163, 184))
        except Exception as e:
            raise ScreenCaptureError(f"Error crítico al generar frame de pantalla: {e}") from e

    # Redimensionar conservando el aspect ratio
    from PIL import Image
    img.thumbnail((max_width, max_height), Image.Resampling.BILINEAR)

    buffer = io.BytesIO()
    img.save(buffer, format="JPEG", quality=quality, optimize=False)
    b64_frame = base64.b64encode(buffer.getvalue()).decode("ascii")

    return {
        "frame": b64_frame,
        "width": img.width,
        "height": img.height,
    }
