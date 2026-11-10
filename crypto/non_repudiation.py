"""Fungsi Non-Repudiation untuk aplikasi SecureDoc.

Membuat signed receipt yang mengikat metadata penandatanganan dengan
Private Key RSA, serta audit trail lokal berbasis hash chain.

Catatan keamanan: audit trail lokal bersifat tamper-evident, bukan immutable.
Pengamanan lebih kuat memerlukan kontrol akses dan penyimpanan eksternal.
"""

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIRECTORY = PROJECT_ROOT / "data"
AUDIT_LOG_PATH = DATA_DIRECTORY / "audit_trail.jsonl"


def _canonical_json(data):
    """Serialisasi JSON deterministik untuk proses penandatanganan/hash."""
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def _timestamp_pair():
    """Kembalikan timestamp UTC dan WIB dari satu waktu yang sama."""
    now_utc = datetime.now(timezone.utc)
    now_wib = now_utc.astimezone(ZoneInfo("Asia/Jakarta"))
    return (
        now_utc.isoformat(timespec="seconds"),
        now_wib.isoformat(timespec="seconds"),
    )


def _public_key_fingerprint(public_key):
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Public Key harus menggunakan algoritma RSA.")

    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(public_der).hexdigest()


def create_signed_receipt(
    document_data,
    document_name,
    document_signature,
    private_key,
    signer_identity,
    signer_fingerprint,
):
    """Buat receipt JSON; payload receipt ditandatangani oleh Private Key.

    Timestamp berasal dari jam sistem aplikasi dan bukan trusted timestamp
    independen dari otoritas timestamp.
    """
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Private Key harus menggunakan algoritma RSA.")

    public_key = private_key.public_key()
    actual_fingerprint = _public_key_fingerprint(public_key)
    if actual_fingerprint != signer_fingerprint:
        raise ValueError("Fingerprint tidak cocok dengan Private Key.")

    required_identity_fields = ("name", "identity_number", "institution")
    if not all(signer_identity.get(field) for field in required_identity_fields):
        raise ValueError("Data identitas penandatangan tidak lengkap.")

    signed_at_utc, signed_at_wib = _timestamp_pair()

    payload = {
        "receipt_version": 1,
        "document": {
            "file_name": str(document_name),
            "sha256": hashlib.sha256(document_data).hexdigest(),
        },
        "signer": {
            "name": signer_identity["name"],
            "identity_number": signer_identity["identity_number"],
            "institution": signer_identity["institution"],
            "public_key_fingerprint_sha256": actual_fingerprint,
        },
        "digital_signature": {
            "signature_file_sha256": hashlib.sha256(document_signature).hexdigest(),
            "signature_algorithm": "RSA-PSS",
            "hash_algorithm": "SHA-256",
            "public_key_size": public_key.key_size,
        },
        # UTC disimpan sebagai waktu kanonis; WIB disertakan untuk tampilan lokal.
        "signed_at_utc": signed_at_utc,
        "signed_at_wib": signed_at_wib,
    }

    receipt_signature = private_key.sign(
        _canonical_json(payload),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    envelope = {
        "payload": payload,
        "receipt_signature": base64.b64encode(receipt_signature).decode("ascii"),
        "receipt_signature_algorithm": "RSA-PSS with SHA-256",
    }

    receipt_bytes = json.dumps(
        envelope,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ).encode("utf-8")

    return receipt_bytes, envelope


def verify_signed_receipt(receipt_data, document_data, document_signature, public_key):
    """Verifikasi signature receipt dan kecocokan receipt dengan file unggahan."""
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Public Key harus menggunakan algoritma RSA.")

    try:
        envelope = json.loads(receipt_data.decode("utf-8"))
        payload = envelope["payload"]
        encoded_signature = envelope["receipt_signature"]
        receipt_signature = base64.b64decode(encoded_signature, validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise ValueError("File receipt JSON tidak valid atau formatnya tidak dikenali.") from error

    if not isinstance(payload, dict):
        raise ValueError("Payload receipt tidak valid.")

    try:
        public_key.verify(
            receipt_signature,
            _canonical_json(payload),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        receipt_signature_valid = True
    except InvalidSignature:
        receipt_signature_valid = False

    document_info = payload.get("document", {})
    signature_info = payload.get("digital_signature", {})
    signer_info = payload.get("signer", {})

    document_hash_matches = (
        document_info.get("sha256") == hashlib.sha256(document_data).hexdigest()
    )
    signature_hash_matches = (
        signature_info.get("signature_file_sha256")
        == hashlib.sha256(document_signature).hexdigest()
    )
    fingerprint_matches = (
        signer_info.get("public_key_fingerprint_sha256")
        == _public_key_fingerprint(public_key)
    )

    return {
        "valid": all((
            receipt_signature_valid,
            document_hash_matches,
            signature_hash_matches,
            fingerprint_matches,
        )),
        "receipt_signature_valid": receipt_signature_valid,
        "document_hash_matches": document_hash_matches,
        "signature_hash_matches": signature_hash_matches,
        "fingerprint_matches": fingerprint_matches,
        "payload": payload,
    }


def append_audit_event(event_type, details):
    """Tambahkan event ke JSONL audit trail dengan hash chain."""
    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)

    previous_hash = "0" * 64
    if AUDIT_LOG_PATH.exists():
        with AUDIT_LOG_PATH.open("r", encoding="utf-8") as log_file:
            for line in log_file:
                if line.strip():
                    try:
                        previous_hash = json.loads(line).get("event_hash", previous_hash)
                    except json.JSONDecodeError as error:
                        raise RuntimeError(
                            "Audit trail rusak. Hentikan pencatatan sampai diperiksa administrator."
                        ) from error

    timestamp_utc, timestamp_wib = _timestamp_pair()
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": str(event_type),
        "timestamp_utc": timestamp_utc,
        "timestamp_wib": timestamp_wib,
        "details": details,
        "previous_hash": previous_hash,
    }
    event_hash = hashlib.sha256(_canonical_json(event)).hexdigest()
    event["event_hash"] = event_hash

    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")

    return event


def read_audit_trail():
    """Baca seluruh event audit trail."""
    if not AUDIT_LOG_PATH.exists():
        return []

    events = []
    with AUDIT_LOG_PATH.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise RuntimeError(f"Audit trail tidak valid pada baris {line_number}.") from error
            events.append(event)
    return events


def verify_audit_trail(events=None):
    """Periksa rantai hash dan urutan event pada audit trail."""
    if events is None:
        events = read_audit_trail()

    expected_previous_hash = "0" * 64

    for index, event in enumerate(events, start=1):
        if event.get("previous_hash") != expected_previous_hash:
            return False, f"Rantai audit terputus pada catatan ke-{index}."

        supplied_hash = event.get("event_hash")
        event_without_hash = {key: value for key, value in event.items() if key != "event_hash"}
        calculated_hash = hashlib.sha256(_canonical_json(event_without_hash)).hexdigest()

        if supplied_hash != calculated_hash:
            return False, f"Isi catatan audit berubah pada catatan ke-{index}."

        expected_previous_hash = supplied_hash

    return True, "Seluruh rantai hash audit trail valid."
