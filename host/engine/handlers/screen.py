"""
Manejador de captura de pantalla en vivo (Live Screen View) con soporte multimonitor.
Captura monitores individuales o el escritorio combinado completo y lo devuelve como JPEG comprimido en Base64.
"""

import base64
import io
import logging
from typing import Dict, Any, List

logger = logging.getLogger("RemoteControler.ScreenHandler")


class ScreenCaptureError(Exception):
    """Excepción para fallos al capturar el frame de pantalla."""
    pass


def capture_screen_jpeg(
    max_width: int = 1280,
    max_height: int = 720,
    quality: int = 70,
    monitor_index: int = 1,
) -> Dict[str, Any]:
    """
    Captura la pantalla solicitada (1=monitor principal, 2..N=secundarios, 0=todas combinadas),
    la escala conservando la relación de aspecto y retorna la imagen JPEG en Base64 junto
    con la información descriptiva de los monitores disponibles.
    """
    img = None
    monitor_count = 1
    selected_index = 1
    monitors_info: List[Dict[str, Any]] = []

    # 1. Intentar captura de alta velocidad con MSS
    try:
        import mss

        with mss.MSS() as sct:
            total_monitors = len(sct.monitors)
            # En MSS, sct.monitors[0] es la suma de todos los monitores.
            # Los monitores físicos individuales empiezan a partir del índice 1.
            if total_monitors > 1:
                monitor_count = total_monitors - 1
                for i in range(1, total_monitors):
                    m = sct.monitors[i]
                    monitors_info.append({
                        "index": i,
                        "width": m["width"],
                        "height": m["height"],
                        "is_primary": m.get("is_primary", i == 1),
                    })
            else:
                monitor_count = 1
                if total_monitors == 1:
                    monitors_info.append({
                        "index": 1,
                        "width": sct.monitors[0]["width"],
                        "height": sct.monitors[0]["height"],
                        "is_primary": True,
                    })

            # Validar índice solicitado
            if monitor_index == 0:
                selected_index = 0
            elif 1 <= monitor_index <= monitor_count:
                selected_index = monitor_index
            else:
                # Fallback seguro al monitor principal
                selected_index = 1 if total_monitors > 1 else 0

            target_monitor = sct.monitors[selected_index]
            raw = sct.grab(target_monitor)

            from PIL import Image
            img = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
    except Exception as e:
        logger.debug("Captura nativa MSS no disponible o falló: %s. Probando fallback.", e)

    # 2. Fallback con PIL ImageGrab si MSS falló
    if img is None:
        try:
            from PIL import ImageGrab
            img = ImageGrab.grab(all_screens=(monitor_index == 0))
            selected_index = 1
            monitor_count = 1
            monitors_info = [{"index": 1, "width": img.width, "height": img.height, "is_primary": True}]
        except Exception as e:
            logger.debug("ImageGrab fallback falló: %s", e)

    # 3. Fallback de contingencia (pantalla bloqueada o entorno headless en CI/CD)
    if img is None:
        try:
            from PIL import Image, ImageDraw
            img = Image.new("RGB", (max_width, max_height), color=(15, 17, 23))
            draw = ImageDraw.Draw(img)
            text = f"Pantalla {monitor_index} no disponible / Sesion bloqueada"
            draw.text((max_width // 4, max_height // 2), text, fill=(148, 163, 184))
            selected_index = monitor_index
            monitor_count = 1
            monitors_info = [{"index": 1, "width": max_width, "height": max_height, "is_primary": True}]
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
        "monitor_index": selected_index,
        "monitor_count": monitor_count,
        "monitors": monitors_info,
    }
