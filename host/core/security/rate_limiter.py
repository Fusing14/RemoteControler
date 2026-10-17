"""
Limitador de tasa adaptativo (Token Bucket) y sistema de castigo (Jail/Ban).
Mitiga ataques de fuerza bruta, DoS de comandos y reintentos tras fallos criptográficos.
"""

import time
import threading
from typing import Dict, Optional, Tuple


class RateLimiter:
    """
    Gestor de tasa de peticiones y bloqueo adaptativo en memoria.
    
    Mitigación de Vectores de Ataque:
    1. Input Flooding & DoS: Limita la cadencia máxima de comandos por segundo por cliente.
    2. Ataques de Fuerza Bruta Criptográfica: Bloquea inmediatamente el identificador/IP
       tras 3 fallos de autenticación consecutivos.
    """

    def __init__(
        self,
        max_rate_per_second: float = 10.0,
        bucket_capacity: float = 15.0,
        max_failures: int = 3,
        base_ban_duration_seconds: float = 300.0,  # 5 minutos
    ) -> None:
        self.max_rate_per_second = max_rate_per_second
        self.bucket_capacity = bucket_capacity
        self.max_failures = max_failures
        self.base_ban_duration = base_ban_duration_seconds

        self._lock = threading.Lock()
        # Token buckets: identifier -> (tokens, last_update_time)
        self._buckets: Dict[str, Tuple[float, float]] = {}
        # Conteo de fallos: identifier -> consecutive_failures
        self._failures: Dict[str, int] = {}
        # Lista de castigo (Jail): identifier -> ban_until_timestamp
        self._banned_until: Dict[str, float] = {}

    def is_banned(self, identifier: str, current_time: Optional[float] = None) -> Tuple[bool, float]:
        """
        Comprueba si un identificador (IP o device_id) se encuentra actualmente suspendido.
        Retorna (True, segundos_restantes) o (False, 0.0).
        """
        now = current_time if current_time is not None else time.time()
        with self._lock:
            ban_time = self._banned_until.get(identifier)
            if ban_time is not None:
                remaining = ban_time - now
                if remaining > 0:
                    return True, remaining
                # El ban ha expirado, limpiar estado
                del self._banned_until[identifier]
                self._failures[identifier] = 0
            return False, 0.0

    def check_rate_limit(self, identifier: str, cost: float = 1.0, current_time: Optional[float] = None) -> bool:
        """
        Aplica el algoritmo Token Bucket.
        Retorna True si la petición es admitida dentro de la cuota, False si excede la tasa.
        """
        now = current_time if current_time is not None else time.time()

        # Si está baneado, rechazo inmediato
        banned, _ = self.is_banned(identifier, current_time=now)
        if banned:
            return False

        with self._lock:
            tokens, last_time = self._buckets.get(identifier, (self.bucket_capacity, now))

            # Recarga de tokens según el tiempo transcurrido
            elapsed = max(0.0, now - last_time)
            tokens = min(self.bucket_capacity, tokens + elapsed * self.max_rate_per_second)

            if tokens >= cost:
                self._buckets[identifier] = (tokens - cost, now)
                return True
            else:
                self._buckets[identifier] = (tokens, now)
                return False

    def record_failure(self, identifier: str, current_time: Optional[float] = None) -> None:
        """
        Registra un intento fallido (firma inválida, dispositivo no reconocido, etc.).
        Si se alcanza max_failures consecutivos, aplica un baneo temporal inmediato.
        """
        now = current_time if current_time is not None else time.time()
        with self._lock:
            count = self._failures.get(identifier, 0) + 1
            self._failures[identifier] = count

            if count >= self.max_failures:
                # Ban adaptativo de 5 minutos
                self._banned_until[identifier] = now + self.base_ban_duration

    def record_success(self, identifier: str) -> None:
        """Restablece el contador de fallos tras una petición autenticada y ejecutada con éxito."""
        with self._lock:
            if identifier in self._failures:
                self._failures[identifier] = 0

    def unban(self, identifier: str) -> None:
        """Desbloquea manualmente un identificador sancionado."""
        with self._lock:
            self._banned_until.pop(identifier, None)
            self._failures.pop(identifier, None)
