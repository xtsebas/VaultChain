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
    Acepta DER (firmado desde Python) y P1363/raw r||s (firmado desde Web Crypto API).
    Retorna True si es valida, False si falla o si hay cualquier error.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        public_key = serialization.load_pem_public_key(ecdsa_public_key_pem.encode('utf-8'))
        sig_bytes = base64.b64decode(signature_b64)
        try:
            public_key.verify(sig_bytes, plaintext, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            # Web Crypto API produce P1363: r||s (64 bytes para P-256)
            if len(sig_bytes) == 64:
                r = int.from_bytes(sig_bytes[:32], 'big')
                s = int.from_bytes(sig_bytes[32:], 'big')
                public_key.verify(encode_dss_signature(r, s), plaintext, ec.ECDSA(hashes.SHA256()))
                return True
            return False
    except Exception:
        return False
