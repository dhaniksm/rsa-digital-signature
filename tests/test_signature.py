from crypto.key_manager import generate_key_pair
from crypto.signature_service import (
    sign_document,
    verify_signature,
)

def test_valid_signature():
    private_key, public_key = generate_key_pair()

    document = b"Dokumen akademik asli"
    signature = sign_document(document, private_key)

    assert verify_signature(
        document, signature, public_key
    ) is True

def test_modified_document():
    private_key, public_key = generate_key_pair()

    original_document = b"Dokumen akademik asli"
    modified_document = b"Dokumen akademik diubah"

    signature = sign_document(
        original_document, private_key
    )

    assert verify_signature(
        modified_document, signature, public_key
    ) is False

def test_wrong_public_key():
    private_key, _ = generate_key_pair()
    _, another_public_key = generate_key_pair()

    document = b"Dokumen pengujian"
    signature = sign_document(document, private_key)

    assert verify_signature(
        document, signature, another_public_key
    ) is False

def test_fake_signature():
    private_key, public_key = generate_key_pair()

    document = b"Dokumen akademik asli"
    fake_signature = b"ini bukan tanda tangan RSA yang valid"

    assert verify_signature(
        document, fake_signature, public_key
    ) is False

def test_empty_document():
    private_key, public_key = generate_key_pair()

    document = b""
    signature = sign_document(document, private_key)

    assert verify_signature(
        document, signature, public_key
    ) is True