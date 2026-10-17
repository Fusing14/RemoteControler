"""
Suite de Pruebas Automatizadas para el Almacenamiento Seguro (Windows DPAPI)
y Gestión de Allowlist de Dispositivos de Confianza.
"""

import time
import pytest
from pathlib import Path

from host.core.storage.dpapi import protect_bytes, unprotect_bytes, DPAPIError
from host.core.storage.device_store import TrustedDeviceStore
from host.core.storage.pairing import PairingManager
from host.core.crypto.signer import (
    generate_ed25519_keypair,
    public_key_to_raw_bytes,
    compute_device_id,
)
from host.core.crypto.verifier import verify_canonical_signature
from host.core.crypto.exceptions import UntrustedDeviceError


def test_dpapi_roundtrip_basic():
    """Prueba 1: Cifrado y descifrado básico en el contexto de usuario actual (CurrentUser)."""
    secret_payload = b"MasterSuperSecretKey_ForHostDaemon_2026"
    encrypted_blob = protect_bytes(secret_payload)

    # Verificar que el texto plano no se encuentra en el blob cifrado
    assert secret_payload not in encrypted_blob

    # Descifrado y comprobación de integridad
    decrypted_payload = unprotect_bytes(encrypted_blob)
    assert decrypted_payload == secret_payload


def test_dpapi_with_secondary_entropy():
    """Prueba 2a: Cifrado con salting/entropía secundaria obligatoria."""
    secret_payload = b"HostEd25519PrivateSeed_99182736"
    secondary_entropy = b"AppSpecificSalt_v1"

    encrypted_blob = protect_bytes(secret_payload, optional_entropy=secondary_entropy)
    decrypted_payload = unprotect_bytes(encrypted_blob, optional_entropy=secondary_entropy)

    assert decrypted_payload == secret_payload


def test_dpapi_failure_on_wrong_or_missing_entropy():
    """Prueba 2b: Fallo garantizado si la entropía no coincide o se omite en el descifrado."""
    secret_payload = b"SensitivePayloadData"
    correct_entropy = b"CorrectEntropyValue"
    wrong_entropy = b"WrongEntropyValue"

    encrypted_blob = protect_bytes(secret_payload, optional_entropy=correct_entropy)

    # Intento de descifrado con entropía incorrecta debe fallar
    with pytest.raises(DPAPIError):
        unprotect_bytes(encrypted_blob, optional_entropy=wrong_entropy)

    # Intento de descifrado omitiendo la entropía debe fallar
    with pytest.raises(DPAPIError):
        unprotect_bytes(encrypted_blob, optional_entropy=None)


def test_device_store_registration_and_revocation(tmp_path: Path):
    """Prueba 3: Registro, consulta y revocación en la Allowlist (Device Pinning)."""
    vault_dir = tmp_path / "vault"
    store = TrustedDeviceStore(vault_dir=vault_dir)

    # Generar identidad simulada para el cliente móvil
    _, mobile_pub = generate_ed25519_keypair()
    mobile_pub_bytes = public_key_to_raw_bytes(mobile_pub)
    device_id = compute_device_id(mobile_pub_bytes)

    # Dispositivo inicialmente no confiable
    assert not store.is_device_trusted(device_id)
    with pytest.raises(UntrustedDeviceError):
        store.get_device_public_key(device_id)

    # 1. Registrar dispositivo
    store.register_device(device_id, mobile_pub_bytes, label="Pixel 9 Pro de Marco")
    assert store.is_device_trusted(device_id)

    retrieved_pub_bytes = store.get_device_public_key(device_id)
    assert retrieved_pub_bytes == mobile_pub_bytes

    # Listar dispositivos autorizados
    devices_list = store.list_trusted_devices()
    assert len(devices_list) == 1
    assert devices_list[0]["device_id"] == device_id
    assert devices_list[0]["label"] == "Pixel 9 Pro de Marco"

    # 2. Revocar dispositivo
    revoked = store.revoke_device(device_id)
    assert revoked is True
    assert not store.is_device_trusted(device_id)

    # Revocar de nuevo debe devolver False
    assert store.revoke_device(device_id) is False


def test_device_store_persistence_across_restarts(tmp_path: Path):
    """Prueba 4: Persistencia cifrada en disco simulando reinicio del servicio."""
    vault_dir = tmp_path / "persistent_vault"
    entropy = b"VaultSalt_RestartTest"

    # 1. Primera ejecución: Se inicializan claves del Host y se registra un cliente
    store_instance_1 = TrustedDeviceStore(vault_dir=vault_dir, secondary_entropy=entropy)
    host_id_1 = store_instance_1.get_host_device_id()
    host_pub_bytes_1 = store_instance_1.get_host_public_key_bytes()

    _, client_pub = generate_ed25519_keypair()
    client_pub_bytes = public_key_to_raw_bytes(client_pub)
    client_device_id = compute_device_id(client_pub_bytes)
    store_instance_1.register_device(client_device_id, client_pub_bytes, label="Tablet Galaxy")

    # Verificar que el archivo en disco está efectivamente cifrado
    vault_file = vault_dir / TrustedDeviceStore.VAULT_FILENAME
    assert vault_file.exists()
    raw_disk_bytes = vault_file.read_bytes()
    assert b"Tablet Galaxy" not in raw_disk_bytes  # Ningún texto plano en disco

    # 2. Simulación de reinicio: Se crea una nueva instancia apuntando al mismo vault
    store_instance_2 = TrustedDeviceStore(vault_dir=vault_dir, secondary_entropy=entropy)

    # Las claves del Host deben ser idénticas
    assert store_instance_2.get_host_device_id() == host_id_1
    assert store_instance_2.get_host_public_key_bytes() == host_pub_bytes_1

    # El dispositivo previamente registrado debe continuar en la Allowlist
    assert store_instance_2.is_device_trusted(client_device_id)
    assert store_instance_2.get_device_public_key(client_device_id) == client_pub_bytes


def test_pairing_challenge_lifecycle(tmp_path: Path):
    """Prueba 5: Generación de token efímero, firma del Host, verificación y consumo único."""
    vault_dir = tmp_path / "pairing_vault"
    store = TrustedDeviceStore(vault_dir=vault_dir)
    pairing_mgr = PairingManager(device_store=store, default_ttl_seconds=180)

    endpoint = "100.85.12.34:8443"
    challenge = pairing_mgr.create_pairing_challenge(tailscale_endpoint=endpoint, ttl_seconds=60)

    # 1. Verificar firma del Host en el desafío
    _, host_pub = store.get_host_keypair()
    verify_canonical_signature(host_pub, challenge.to_canonical_dict(), challenge.signature)

    # 2. Consumo exitoso con el token correcto
    token = challenge.pairing_token
    assert pairing_mgr.verify_and_consume_token(token) is True

    # 3. Mitigación de Replay: El token ya fue consumido (One-Time Token)
    assert pairing_mgr.verify_and_consume_token(token) is False


def test_pairing_challenge_expiration(tmp_path: Path):
    """Prueba 6: Desafío de emparejamiento expira tras transcurrir su TTL."""
    vault_dir = tmp_path / "exp_vault"
    store = TrustedDeviceStore(vault_dir=vault_dir)
    pairing_mgr = PairingManager(device_store=store, default_ttl_seconds=10)

    challenge = pairing_mgr.create_pairing_challenge(tailscale_endpoint="100.1.2.3:8443", ttl_seconds=10)
    token = challenge.pairing_token

    # Simular tiempo futuro mayor al TTL (15 segundos después)
    future_time = time.time() + 15
    assert pairing_mgr.verify_and_consume_token(token, current_time=future_time) is False


def test_pairing_challenge_inter_process_persistence(tmp_path: Path):
    """
    Prueba 7: Simulación inter-proceso entre 'host.main pair' (CLI) y 'host.main run' (Daemon).
    Verifica que una instancia separada de PairingManager puede leer, validar y consumir
    el desafío persistido en disco con DPAPI.
    """
    vault_dir = tmp_path / "ipc_pairing_vault"
    
    # Proceso 1 ('pair'): genera el QR y persiste en disco
    store_pair_cli = TrustedDeviceStore(vault_dir=vault_dir)
    mgr_pair_cli = PairingManager(device_store=store_pair_cli, default_ttl_seconds=300)
    challenge = mgr_pair_cli.create_pairing_challenge(tailscale_endpoint="100.73.194.76:8443", ttl_seconds=300)
    token = challenge.pairing_token

    # Comprobar que el archivo cifrado existe en disco
    assert mgr_pair_cli.challenge_path.exists()

    # Proceso 2 ('run'): daemon separado que recibe POST /pair
    store_daemon = TrustedDeviceStore(vault_dir=vault_dir)
    mgr_daemon = PairingManager(device_store=store_daemon)

    # 1. Intento con token erróneo debe fallar
    assert mgr_daemon.verify_and_consume_token("bad_token_12345") is False
    assert "no coincide" in mgr_daemon.last_rejection_reason

    # 2. Intento con el token legítimo emitido por el proceso 1
    assert mgr_daemon.verify_and_consume_token(token) is True
    assert mgr_daemon.last_rejection_reason is None

    # 3. Tras el consumo, el archivo en disco debe haber sido eliminado
    assert not mgr_daemon.challenge_path.exists()

    # 4. Segundo intento debe ser rechazado como Replay / Ya consumido
    assert mgr_daemon.verify_and_consume_token(token) is False
    assert "No hay ningún desafío" in mgr_daemon.last_rejection_reason

