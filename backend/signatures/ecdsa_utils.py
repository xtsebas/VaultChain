import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def sign_message(plaintext: bytes, ecdsa_private_key_pem: str) -> str:
    """
    Firma el hash SHA-256 del plaintext con la llave privada ECDSA P-256.
    Retorna la firma en base64 (formato DER).
    """
    private_key = serialization.load_pem_private_key(
        ecdsa_private_key_pem.encode('utf-8'),
        password=None,
    )
    signature_der = private_key.sign(plaintext, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature_der).decode('utf-8')


def verify_signature(plaintext: bytes, signature_b64: str, ecdsa_public_key_pem: str) -> bool:
    """
    Verifica la firma ECDSA contra el hash SHA-256 del plaintext.
    Retorna True si es valida, False si falla o si hay cualquier error.
    """
    try:
        public_key = serialization.load_pem_public_key(ecdsa_public_key_pem.encode('utf-8'))
        signature_der = base64.b64decode(signature_b64)
        public_key.verify(signature_der, plaintext, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False
