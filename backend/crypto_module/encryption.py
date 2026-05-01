import os
import base64

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


def generate_aes_key() -> bytes:
    return os.urandom(32)


def generate_nonce() -> bytes:
    return os.urandom(12)


def encrypt_aes_gcm(plaintext: bytes, aes_key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, auth_tag


def encrypt_key_rsa_oaep(aes_key: bytes, recipient_public_key_pem: str) -> bytes:
    rsa_key = RSA.import_key(recipient_public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    return cipher_rsa.encrypt(aes_key)


def encrypt_message(plaintext: str | bytes, recipient_public_key_pem: str) -> dict:
    """
    Cifra un mensaje con AES-256-GCM y encripta la clave AES con RSA-OAEP.

    Retorna un dict con ciphertext, encrypted_key, nonce y auth_tag en Base64.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    aes_key = generate_aes_key()
    nonce = generate_nonce()

    ciphertext, auth_tag = encrypt_aes_gcm(plaintext, aes_key, nonce)
    encrypted_key = encrypt_key_rsa_oaep(aes_key, recipient_public_key_pem)

    return {
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "auth_tag": base64.b64encode(auth_tag).decode("utf-8"),
    }


def decrypt_aes_gcm(
    ciphertext: bytes, auth_tag: bytes, aes_key: bytes, nonce: bytes
) -> bytes:
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, auth_tag)


def decrypt_key_rsa_oaep(encrypted_key: bytes, recipient_private_key_pem: str) -> bytes:
    rsa_key = RSA.import_key(recipient_private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    return cipher_rsa.decrypt(encrypted_key)


def decrypt_message(
    ciphertext_b64: str,
    encrypted_key_b64: str,
    nonce_b64: str,
    auth_tag_b64: str,
    recipient_private_key_pem: str,
) -> bytes:
    """
    Descifra un mensaje. Invierte exactamente lo que hace encrypt_message.

    Lanza ValueError si el auth_tag no coincide (mensaje alterado).
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    encrypted_key = base64.b64decode(encrypted_key_b64)
    nonce = base64.b64decode(nonce_b64)
    auth_tag = base64.b64decode(auth_tag_b64)

    aes_key = decrypt_key_rsa_oaep(encrypted_key, recipient_private_key_pem)
    return decrypt_aes_gcm(ciphertext, auth_tag, aes_key, nonce)
