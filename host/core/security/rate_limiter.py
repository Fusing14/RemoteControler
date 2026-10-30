"""
Limitador de tasa adaptativo (Token Bucket) y sistema de castigo con Exponential Backoff (Jail/Ban).
Mitiga ataques de fuerza bruta (CWE-307), DoS de comandos (CWE-400) y reintentos tras fallos criptográficos.
"""

import time
import threading
from typing import Dict, Optional, Tuple


class RateLimiter:
    """
    Gestor de tasa de peticiones y bloqueo adaptativo en memoria con Exponential Backoff.
    
    Mitigación de Vectores de Ataque:
    1. Input Flooding & DoS: Limita la cadencia máxima de comandos por segundo por cliente.
    2. Ataques de Fuerza Bruta Criptográfica (CWE-307): Bloquea inmediatamente el identificador/IP
       tras alcanzar max_failures fallos consecutivos, aplicando Exponential Backoff en reincidencias
       (ej. 5 min -> 10 min -> 20 min -> máx 60 min).
    """

    def __init__(
        self,
        max_rate_per_second: float = 10.0,
        bucket_capacity: float = 15.0,
        max_failures: int = 3,
        base_ban_duration_seconds: float = 300.0,  # 5 minutos base
        max_ban_duration_seconds: float = 3600.0,  # 1 hora máximo
    ) -> None:
        self.max_rate_per_second = max_rate_per_second
        self.bucket_capacity = bucket_capacity
        self.max_failures = max_failures
        self.base_ban_duration = base_ban_duration_seconds
        self.max_ban_duration = max(base_ban_duration_seconds, max_ban_duration_seconds)

        self._lock = threading.Lock()
        # Token buckets: identifier -> (tokens, last_update_time)
        self._buckets: Dict[str, Tuple[float, float]] = {}
        # Conteo de fallos consecutivos: identifier -> consecutive_failures
        self._failures: Dict[str, int] = {}
        # Nivel de reincidencia para Exponential Backoff: identifier -> offense_count
        self._ban_offenses: Dict[str, int] = {}
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
                # El ban ha expirado, limpiar estado de bloqueo activo pero conservar historial de reincidencia
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

    def record_failure(self, identifier: str, current_time: Optional[float] = None) -> float:
        """
        Registra un intento fallido (firma inválida, PIN erróneo, token inválido, etc.).
        Si se alcanza max_failures consecutivos, aplica un baneo temporal con Exponential Backoff.
        Retorna la duración del baneo aplicado (0.0 si aún no fue baneado).
        """
        now = current_time if current_time is not None else time.time()
        with self._lock:
            count = self._failures.get(identifier, 0) + 1
            self._failures[identifier] = count

            if count >= self.max_failures:
                offense = self._ban_offenses.get(identifier, 0) + 1
                self._ban_offenses[identifier] = offense
                self._failures[identifier] = 0
                multiplier = 2 ** (offense - 1)
                ban_duration = min(self.max_ban_duration, self.base_ban_duration * multiplier)
                self._banned_until[identifier] = now + ban_duration
                return ban_duration
            return 0.0

    def get_failure_count(self, identifier: str) -> int:
        """Retorna el número de fallos consecutivos acumulados para un identificador."""
        with self._lock:
            return self._failures.get(identifier, 0)

    def get_ban_offenses(self, identifier: str) -> int:
        """Retorna el nivel de reincidencia (Exponential Backoff) de un identificador."""
        with self._lock:
            return self._ban_offenses.get(identifier, 0)

    def record_success(self, identifier: str) -> None:
        """Restablece el contador de fallos tras una petición autenticada y ejecutada con éxito."""
        with self._lock:
            self._failures.pop(identifier, None)
            self._ban_offenses.pop(identifier, None)

    def unban(self, identifier: str) -> None:
        """Desbloquea manualmente un identificador sancionado."""
        with self._lock:
            self._banned_until.pop(identifier, None)
            self._failures.pop(identifier, None)
            self._ban_offenses.pop(identifier, None)
