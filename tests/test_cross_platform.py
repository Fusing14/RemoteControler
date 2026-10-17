"""
Prueba de interoperabilidad criptográfica cruzada: Dart (Móvil) <-> Python (Host).
Demuestra matemáticamente que el SignedEnvelope firmado por el código en Dart
es verificado y despachado con éxito por el daemon en Python bajo RFC 8785.
"""

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch
import pytest

from host.engine.contracts.commands import CommandCatalog, MediaAction
from host.engine.contracts.envelope import SignedEnvelope
from host.engine.dispatcher import CommandDispatcher, ExecutionStatus
from host.core.storage.device_store import TrustedDeviceStore
from host.core.security.anti_replay import AntiReplayValidator


def test_cross_platform_dart_signed_envelope(tmp_path: Path):
    """
    1. Ejecuta script en Dart que inicializa KeyManager y firma un SignedEnvelope.
    2. Python recibe el JSON generado por Dart.
    3. Host valida el envelope con Pydantic, verifica Device Pinning y firma Ed25519.
    """
    dart_bin = shutil.which("dart")
    if not dart_bin:
        pytest.skip("Dart SDK no disponible en PATH.")

    mobile_dir = Path(__file__).parent.parent / "mobile"
    scratch_dart = mobile_dir / "test" / "scratch_envelope.dart"
    scratch_dart.parent.mkdir(parents=True, exist_ok=True)

    dart_script = """
import 'dart:convert';
import 'package:remote_controler_mobile/crypto/key_manager.dart';
import 'package:remote_controler_mobile/protocol/envelope_builder.dart';

void main() async {
  final storage = MemorySecureStorageAdapter();
  final km = KeyManager(storage: storage);
  await km.initialize();

  final builder = EnvelopeBuilder(keyManager: km);
  final envelope = await builder.buildSignedEnvelope(
    commandId: 'MEDIA',
    payload: {'action': 'PLAY_PAUSE'},
  );

  print(json.encode({
    'envelope': envelope,
    'public_key_hex': km.publicKeyHex,
    'device_id': km.deviceId,
  }));
}
"""
    try:
        scratch_dart.write_text(dart_script, encoding="utf-8")

        res = subprocess.run(
            [dart_bin, "run", str(scratch_dart)],
            cwd=str(mobile_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

        assert res.returncode == 0, f"Error en Dart: {res.stderr}"

        output_lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
        dart_output = json.loads(output_lines[-1])

        envelope_dict = dart_output["envelope"]
        public_key_hex = dart_output["public_key_hex"]
        device_id = dart_output["device_id"]

        # 1. Validar deserialización en Python vía Pydantic V2
        envelope = SignedEnvelope.model_validate(envelope_dict)
        assert envelope.device_id == device_id
        assert envelope.command_id == CommandCatalog.MEDIA

        # 2. Configurar entorno del Host en Python
        vault_dir = tmp_path / "host_vault"
        device_store = TrustedDeviceStore(vault_dir=vault_dir)
        anti_replay = AntiReplayValidator()
        dispatcher = CommandDispatcher(device_store, anti_replay)

        # 3. Registrar la clave pública del móvil en la Allowlist
        pub_bytes = bytes.fromhex(public_key_hex)
        device_store.register_device(device_id, pub_bytes, label="Flutter Pixel 9")

        # 4. Despachar comando emitido por Dart en el Host
        with patch("host.engine.handlers.media.send_virtual_key") as mock_vk:
            exec_result = dispatcher.dispatch(envelope)
            assert exec_result.status == ExecutionStatus.SUCCESS
            assert exec_result.command_id == "MEDIA"
            assert mock_vk.called
    finally:
        if scratch_dart.exists():
            scratch_dart.unlink()
