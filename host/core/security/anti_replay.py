"""
Módulo de protección Anti-Replay y validación de frescura temporal.
Mitiga ataques de repetición mediante ventana deslizante y caché de nonces con auto-expiración.
"""

import time
import threading
from typing import Dict, Optional

from host.core.crypto.exceptions import ClockSkewError, ReplayAttackDetectedError


class AntiReplayValidator:
    """
    Gestor de validación de marcas temporales y nonces únicos.
    
    Mitigación de Vectores de Ataque:
    1. Replay Attacks: Impide la retransmisión de paquetes previamente firmados mediante
       un almacén de nonces con TTL acotado.
    2. Delayed Execution: Descarta comandos transmitidos fuera de la ventana de sincronización.
    """

    def __init__(
        self,
        max_clock_skew_seconds: int = 30,
        nonce_ttl_seconds: int = 60,
    ) -> None:
        """
        :param max_clock_skew_seconds: Desfase máximo permitido entre el reloj del cliente y el host (segundos).
        :param nonce_ttl_seconds: Tiempo de vida del nonce en memoria (segundos).
                                  Debe ser estrictamente superior a 2 * max_clock_skew_seconds
                                  para garantizar que un nonce caduque solo cuando la marca de tiempo
                                  ya esté fuera de la ventana aceptable.
        """
        if nonce_ttl_seconds < max_clock_skew_seconds * 2:
            raise ValueError(
                f"nonce_ttl ({nonce_ttl_seconds}s) debe ser al menos el doble de max_clock_skew ({max_clock_skew_seconds}s)"
            )

        self.max_clock_skew_seconds = max_clock_skew_seconds
        self.nonce_ttl_seconds = nonce_ttl_seconds
        self._lock = threading.Lock()
        # Mapeo: nonce -> timestamp de expiración (float Unix Epoch)
        self._seen_nonces: Dict[str, float] = {}

    def _cleanup_expired(self, current_time: float) -> None:
        """Purga nonces cuya fecha de expiración haya pasado para evitar consumo de memoria."""
        expired = [nonce for nonce, exp in self._seen_nonces.items() if exp <= current_time]
        for nonce in expired:
            del self._seen_nonces[nonce]

    def validate_timestamp(self, timestamp_utc: int, current_time: Optional[float] = None) -> None:
        """
        Verifica que el timestamp se encuentre dentro de la ventana de tolerancia admitida.
        Lanza ClockSkewError si el desfase excede max_clock_skew_seconds.
        """
        now = current_time if current_time is not None else time.time()
        drift = abs(now - timestamp_utc)
        if drift > self.max_clock_skew_seconds:
            raise ClockSkewError(
                f"Desfase de reloj detectado ({drift:.2f}s). Límite permitido: {self.max_clock_skew_seconds}s"
            )

    def record_and_verify_nonce(self, nonce: str, current_time: Optional[float] = None) -> None:
        """
        Comprueba que el nonce no haya sido visto. Si es nuevo, lo almacena con su TTL.
        Lanza ReplayAttackDetectedError si el nonce ya existe en la caché.
        """
        now = current_time if current_time is not None else time.time()

        with self._lock:
            self._cleanup_expired(now)

            if nonce in self._seen_nonces:
                raise ReplayAttackDetectedError(
                    f"Ataque de repetición detectado: el nonce '{nonce}' ya fue utilizado y está en caché activa."
                )

            # Registrar el nonce con su instante de expiración
            self._seen_nonces[nonce] = now + self.nonce_ttl_seconds

    def validate(self, timestamp_utc: int, nonce: str, current_time: Optional[float] = None) -> None:
        """
        Validación atómica de frescura:
        1. Valida ventana de reloj (falla rápido antes de tocar la caché).
        2. Valida unicidad de nonce y lo registra.
        """
        now = current_time if current_time is not None else time.time()
        self.validate_timestamp(timestamp_utc, current_time=now)
        self.record_and_verify_nonce(nonce, current_time=now)

    @property
    def active_nonces_count(self) -> int:
        """Retorna la cantidad de nonces activos actualmente en memoria (útil para auditoría)."""
        with self._lock:
            return len(self._seen_nonces)
