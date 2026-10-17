"""
Manejador de recepción y reproducción de audio en tiempo real (Intercom / Walkie-Talkie).
Recibe fragmentos de audio PCM de 16-bit mono codificados en Base64 desde el dispositivo móvil,
los empaqueta con encabezado WAV estándar en memoria y los reproduce de forma asíncrona
en los altavoces predeterminados del PC mediante un worker thread dedicado y winsound nativo de Windows.
"""

import base64
import logging
import queue
import struct
import sys
import threading
from typing import Optional

logger = logging.getLogger("RemoteControler.AudioStream")


class AudioStreamError(Exception):
    """Excepción para fallos en el procesamiento o reproducción del flujo de audio."""
    pass


def _create_wav_header(
    pcm_length: int,
    sample_rate: int = 16000,
    channels: int = 1,
    bits_per_sample: int = 16,
) -> bytes:
    """Construye un encabezado RIFF/WAVE estándar de 44 bytes para datos PCM."""
    byte_rate = sample_rate * channels * (bits_per_sample // 8)
    block_align = channels * (bits_per_sample // 8)
    total_chunk_size = 36 + pcm_length

    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        total_chunk_size,
        b"WAVE",
        b"fmt ",
        16,  # Subchunk1Size para formato PCM
        1,   # AudioFormat (1 = PCM lineal sin compresión)
        channels,
        sample_rate,
        byte_rate,
        block_align,
        bits_per_sample,
        b"data",
        pcm_length,
    )
    return header


class AudioPlayerWorker:
    """
    Reproductor de audio en segundo plano con cola acotada para garantizar baja latencia (<250ms).
    Descarta fragmentos acumulados en caso de congestión para mantener la sincronía en vivo.
    """

    _instance: Optional["AudioPlayerWorker"] = None
    _lock = threading.Lock()

    def __init__(self, max_queue_size: int = 25) -> None:
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._is_running = True
        self._thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="AudioPlayerWorker",
        )
        self._thread.start()

    @classmethod
    def get_instance(cls) -> "AudioPlayerWorker":
        with cls._lock:
            if cls._instance is None:
                cls._instance = AudioPlayerWorker()
            return cls._instance

    def _worker_loop(self) -> None:
        while self._is_running:
            try:
                first_item = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            raw_pcm, sample_rate, channels = first_item
            accumulated = [raw_pcm]

            # Drenar paquetes inmediatamente contiguos en cola para concatenarlos
            # y reproducirlos en un único bloque continuo, reduciendo drásticamente
            # las aperturas del dispositivo de sonido y eliminando chasquidos entre fragmentos.
            while not self._queue.empty() and len(accumulated) < 4:
                try:
                    next_pcm, next_rate, next_ch = self._queue.get_nowait()
                    if next_rate == sample_rate and next_ch == channels:
                        accumulated.append(next_pcm)
                        self._queue.task_done()
                    else:
                        self._queue.put_nowait((next_pcm, next_rate, next_ch))
                        break
                except (queue.Empty, queue.Full):
                    break

            combined_pcm = b"".join(accumulated)
            header = _create_wav_header(
                pcm_length=len(combined_pcm),
                sample_rate=sample_rate,
                channels=channels,
                bits_per_sample=16,
            )
            wav_data = header + combined_pcm

            try:
                if sys.platform == "win32":
                    import winsound
                    # SND_MEMORY reproduce el buffer WAV directamente en memoria dentro del worker thread
                    winsound.PlaySound(wav_data, winsound.SND_MEMORY)
            except Exception as e:
                logger.warning("Fallo al reproducir fragmento de audio: %s", e)
            finally:
                self._queue.task_done()

    def enqueue_chunk(
        self,
        raw_pcm: bytes,
        sample_rate: int = 16000,
        channels: int = 1,
    ) -> None:
        if not raw_pcm:
            return

        # Si hay más de 12 paquetes en cola, descartar los más antiguos para preservar baja latencia
        while self._queue.qsize() > 12:
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except queue.Empty:
                break

        try:
            self._queue.put_nowait((raw_pcm, sample_rate, channels))
        except queue.Full:
            pass  # Descartar si la cola sigue saturada para no bloquear la red


def play_audio_chunk(
    audio_b64: str,
    sample_rate: int = 16000,
    channels: int = 1,
) -> None:
    """
    Decodifica y encola un fragmento de audio PCM recibido para reproducción inmediata.
    """
    if len(audio_b64) > 32768:
        raise AudioStreamError("Fragmento de audio codificado excede el tamaño máximo permitido (32 KB).")

    try:
        raw_pcm = base64.b64decode(audio_b64, validate=True)
    except Exception as e:
        raise AudioStreamError(f"Datos de audio Base64 inválidos: {e}") from e

    if len(raw_pcm) > 32768:
        raise AudioStreamError("Fragmento de audio PCM decodificado excede el límite máximo (32 KB).")

    player = AudioPlayerWorker.get_instance()
    player.enqueue_chunk(raw_pcm, sample_rate=sample_rate, channels=channels)
