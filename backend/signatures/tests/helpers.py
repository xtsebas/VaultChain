from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from crypto_module.tests.helpers import make_crypto_user


def generate_ecdsa_pair():
    """Genera un par ECDSA P-256 y los retorna como strings PEM."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode('utf-8')
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')
    return private_pem, public_pem


def make_ecdsa_user(email, display_name):
    """Crea un usuario con par RSA (para cifrado) y par ECDSA P-256 (para firmas)."""
    user, rsa_private_pem = make_crypto_user(email=email, display_name=display_name)
    ecdsa_private_pem, ecdsa_public_pem = generate_ecdsa_pair()
    user.ecdsa_public_key = ecdsa_public_pem
    user.encrypted_ecdsa_private_key = 'placeholder'
    user.save(update_fields=['ecdsa_public_key', 'encrypted_ecdsa_private_key'])
    return user, ecdsa_private_pem
