import base64

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


def decrypt_key_rsa_oaep(encrypted_key: bytes, recipient_private_key_pem: str) -> bytes:
    rsa_key = RSA.import_key(recipient_private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    return cipher_rsa.decrypt(encrypted_key)


def decrypt_aes_gcm(
    ciphertext: bytes, auth_tag: bytes, aes_key: bytes, nonce: bytes
) -> bytes:
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, auth_tag)


def decrypt_message(
    ciphertext_b64: str,
    encrypted_key_b64: str,
    nonce_b64: str,
    auth_tag_b64: str,
    recipient_private_key_pem: str,
) -> bytes:
    """
    Descifra un mensaje cifrado con encrypt_message.

    Recupera la clave AES con RSA-OAEP usando la llave privada del destinatario,
    luego descifra con AES-256-GCM verificando el auth_tag.
    Lanza ValueError si el auth_tag no coincide (mensaje alterado).
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    encrypted_key = base64.b64decode(encrypted_key_b64)
    nonce = base64.b64decode(nonce_b64)
    auth_tag = base64.b64decode(auth_tag_b64)

    aes_key = decrypt_key_rsa_oaep(encrypted_key, recipient_private_key_pem)
    return decrypt_aes_gcm(ciphertext, auth_tag, aes_key, nonce)
