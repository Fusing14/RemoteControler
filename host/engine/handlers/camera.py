"""
Manejador de captura de webcam en tiempo real (Live Webcam Stream).
Captura fotogramas de la cámara web predeterminada de Windows mediante OpenCV,
los redimensiona y comprime a JPEG codificado en Base64.
Gestiona el ciclo de vida del dispositivo liberándolo adecuadamente tras inactividad.
"""

import base64
import logging
import sys
import threading
from typing import Dict, Any, Optional

logger = logging.getLogger("RemoteControler.CameraHandler")


class CameraCaptureError(Exception):
    """Excepción para fallos al capturar fotogramas de la cámara web."""
    pass


class CameraManager:
    """
    Gestor con exclusión mutua y auto-liberación para la captura de video de la webcam.
    Mantiene la cámara abierta durante secuencias de streaming activas para alto rendimiento (15-30 FPS)
    y programa la liberación automática del dispositivo tras 2.5 segundos de inactividad,
    evitando bloqueos del hardware en Windows.
    """

    _instance: Optional["CameraManager"] = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self._cap = None
        self._current_index: Optional[int] = None
        self._release_timer: Optional[threading.Timer] = None
        self._capture_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "CameraManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = CameraManager()
            return cls._instance

    def _auto_release(self) -> None:
        with self._capture_lock:
            if self._cap is not None:
                try:
                    self._cap.release()
                    logger.info("Recurso de cámara %s liberado por inactividad.", self._current_index)
                except Exception as e:
                    logger.warning("Error al liberar recurso de cámara: %s", e)
                finally:
                    self._cap = None
                    self._current_index = None
                    self._release_timer = None

    def release(self) -> None:
        """Libera inmediatamente el recurso de la cámara."""
        with self._capture_lock:
            if self._release_timer:
                self._release_timer.cancel()
                self._release_timer = None
            if self._cap is not None:
                try:
                    self._cap.release()
                    logger.info("Recurso de cámara liberado explícitamente.")
                except Exception as e:
                    logger.warning("Error al liberar cámara: %s", e)
                finally:
                    self._cap = None
                    self._current_index = None

    def capture_frame(
        self,
        camera_index: int = 0,
        max_width: int = 854,
        max_height: int = 480,
        quality: int = 65,
    ) -> Dict[str, Any]:
        """
        Captura un fotograma de la cámara especificada y lo devuelve comprimido en JPEG (Base64).
        """
        with self._capture_lock:
            # Cancelar temporizador de auto-liberación previo si sigue activo
            if self._release_timer:
                self._release_timer.cancel()
                self._release_timer = None

            import cv2

            # Reutilizar captura si ya está abierta con el mismo índice
            if self._cap is None or self._current_index != camera_index or not self._cap.isOpened():
                if self._cap is not None:
                    try:
                        self._cap.release()
                    except Exception:
                        pass

                api_preference = cv2.CAP_DSHOW if sys.platform == "win32" else cv2.CAP_ANY
                self._cap = cv2.VideoCapture(camera_index, api_preference)
                self._current_index = camera_index

            frame = None
            if self._cap.isOpened():
                ret, captured = self._cap.read()
                if ret and captured is not None:
                    frame = captured

            # Programar liberación automática tras 2.5s sin peticiones
            self._release_timer = threading.Timer(2.5, self._auto_release)
            self._release_timer.daemon = True
            self._release_timer.start()

            # Fallback en caso de cámara no disponible o entornos sin webcam física (ej. CI/CD)
            if frame is None:
                logger.warning("No se pudo obtener imagen de la webcam %d. Generando frame de contingencia.", camera_index)
                import numpy as np

                fallback_w = min(max_width, 640)
                fallback_h = min(max_height, 480)
                frame = np.zeros((fallback_h, fallback_w, 3), dtype=np.uint8)
                cv2.putText(
                    frame,
                    f"Camara {camera_index} no disponible",
                    (20, fallback_h // 2),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.6,
                    (148, 163, 184),
                    2,
                )

            # Redimensionar conservando aspect ratio si supera los máximos
            h, w = frame.shape[:2]
            if w > max_width or h > max_height:
                scale = min(max_width / w, max_height / h)
                new_w, new_h = max(1, int(w * scale)), max(1, int(h * scale))
                frame = cv2.resize(frame, (new_w, new_h), interpolation=cv2.INTER_AREA)

            # Comprimir a JPEG
            encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), max(30, min(95, quality))]
            success, enc_buf = cv2.imencode(".jpg", frame, encode_params)
            if not success or enc_buf is None:
                raise CameraCaptureError("Fallo al codificar el fotograma a formato JPEG.")

            b64_frame = base64.b64encode(enc_buf.tobytes()).decode("ascii")
            h, w = frame.shape[:2]

            return {
                "frame": b64_frame,
                "width": w,
                "height": h,
                "camera_index": camera_index,
            }


def capture_camera_jpeg(
    camera_index: int = 0,
    max_width: int = 854,
    max_height: int = 480,
    quality: int = 65,
) -> Dict[str, Any]:
    """
    Función de conveniencia para capturar un fotograma de la webcam.
    """
    manager = CameraManager.get_instance()
    return manager.capture_frame(
        camera_index=camera_index,
        max_width=max_width,
        max_height=max_height,
        quality=quality,
    )


def release_camera() -> None:
    """Libera el recurso de la cámara inmediatamente."""
    manager = CameraManager.get_instance()
    manager.release()
