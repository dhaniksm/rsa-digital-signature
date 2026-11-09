from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, file_path, password=None):
    if password:
        encryption = serialization.BestAvailableEncryption(
            password.encode("utf-8")
        )
    else:
        encryption = serialization.NoEncryption()

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    with open(file_path, "wb") as file:
        file.write(pem_data)


def save_public_key(public_key, file_path):
    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(file_path, "wb") as file:
        file.write(pem_data)


def load_private_key(file_path, password=None):
    password_bytes = (
        password.encode("utf-8")
        if password is not None
        else None
    )

    with open(file_path, "rb") as file:
        return serialization.load_pem_private_key(
            file.read(),
            password=password_bytes
        )


def load_public_key(file_path):
    with open(file_path, "rb") as file:
        return serialization.load_pem_public_key(file.read())