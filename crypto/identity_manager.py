"""
Pengelolaan identitas tepercaya untuk SecureDoc.

Registry ini menghubungkan fingerprint Public Key RSA dengan identitas
penandatangan. Untuk proyek akademik, file JSON ini berfungsi sebagai
trusted registry lokal yang dikelola administrator.
"""

import hashlib
import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIRECTORY = PROJECT_ROOT / "data"
REGISTRY_PATH = DATA_DIRECTORY / "identity_registry.json"


def get_public_key_fingerprint(public_key):
    """
    Menghasilkan fingerprint SHA-256 dari Public Key dalam format DER
    SubjectPublicKeyInfo. Format DER dipakai agar fingerprint konsisten.
    """
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Public Key harus menggunakan algoritma RSA.")

    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return hashlib.sha256(public_key_der).hexdigest()


def _load_registry():
    """Membaca registry identitas. Registry kosong dibuat saat pertama kali dipakai."""
    if not REGISTRY_PATH.exists():
        return {"identities": {}}

    try:
        registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(
            "File registry identitas tidak dapat dibaca. "
            "Periksa data/identity_registry.json."
        ) from error

    if not isinstance(registry, dict) or not isinstance(
        registry.get("identities"), dict
    ):
        raise RuntimeError("Format registry identitas tidak valid.")

    return registry


def _save_registry(registry):
    """Menyimpan registry secara atomik agar file tidak setengah tertulis."""
    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)

    temporary_path = REGISTRY_PATH.with_suffix(".tmp")
    temporary_path.write_text(
        json.dumps(registry, ensure_ascii=False, indent=4),
        encoding="utf-8"
    )
    temporary_path.replace(REGISTRY_PATH)


def register_identity(public_key, name, identity_number, institution):
    """
    Mendaftarkan fingerprint Public Key RSA ke identitas penandatangan.

    Pendaftaran harus dipanggil dari alur administrator yang tepercaya.
    """
    name = str(name).strip()
    identity_number = str(identity_number).strip()
    institution = str(institution).strip()

    if not name or not identity_number or not institution:
        raise ValueError("Nama, NIM/NIP, dan instansi wajib diisi.")

    fingerprint = get_public_key_fingerprint(public_key)
    registry = _load_registry()
    identities = registry["identities"]

    if fingerprint in identities:
        existing = identities[fingerprint]
        raise ValueError(
            "Public Key ini sudah terdaftar atas nama "
            f"{existing.get('name', 'identitas lain')}."
        )

    # Satu nomor identitas hanya boleh terhubung ke satu Public Key
    # dalam versi awal aplikasi ini.
    for existing_fingerprint, existing in identities.items():
        if existing.get("identity_number", "").casefold() == identity_number.casefold():
            raise ValueError(
                "NIM/NIP tersebut sudah terdaftar dengan Public Key lain."
            )

    registered_now = datetime.now(timezone.utc)
    registered_at = registered_now.isoformat(timespec="seconds")
    registered_at_wib = registered_now.astimezone(
        ZoneInfo("Asia/Jakarta")
    ).isoformat(timespec="seconds")

    identities[fingerprint] = {
        "name": name,
        "identity_number": identity_number,
        "institution": institution,
        "registered_at": registered_at,
        "registered_at_wib": registered_at_wib,
        "fingerprint": fingerprint
    }

    _save_registry(registry)
    return fingerprint


def get_registered_identity(public_key):
    """Mengembalikan data identitas jika fingerprint Public Key terdaftar."""
    fingerprint = get_public_key_fingerprint(public_key)
    identity = _load_registry()["identities"].get(fingerprint)

    if identity is None:
        return None

    return dict(identity)


def list_registered_identities():
    """Mengembalikan daftar identitas yang terdaftar untuk ditampilkan admin."""
    identities = _load_registry()["identities"]

    return [
        dict(identity)
        for identity in sorted(
            identities.values(),
            key=lambda item: item.get("registered_at", "")
        )
    ]
