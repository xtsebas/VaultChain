import os
import base64

from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import User
from .serializers import RegisterSerializer


class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        email = data['email']
        display_name = data['display_name']
        password = data['password']

        if User.objects.filter(email=email).exists():
            return Response(
                {'email': 'Email already registered.'},
                status=status.HTTP_409_CONFLICT,
            )

        # Hash password with Argon2id
        ph = PasswordHasher()
        password_hash = ph.hash(password)

        # Generate ECC P-256 key pair
        private_key = generate_private_key(SECP256R1())
        public_key_pem = private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        private_key_der = private_key.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )

        # Derive 256-bit key from password using PBKDF2-SHA256 (600k iterations)
        pbkdf2_salt = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=pbkdf2_salt,
            iterations=600_000,
        )
        derived_key = kdf.derive(password.encode('utf-8'))

        # Encrypt private key with AES-256-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(derived_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, private_key_der, None)

        # Format: base64(salt):base64(nonce):base64(ciphertext+tag)
        encrypted_private_key = ':'.join([
            base64.b64encode(pbkdf2_salt).decode(),
            base64.b64encode(nonce).decode(),
            base64.b64encode(ciphertext_with_tag).decode(),
        ])

        user = User(
            email=email,
            display_name=display_name,
            password_hash=password_hash,
            public_key=public_key_pem,
            encrypted_private_key=encrypted_private_key,
        )
        user.set_unusable_password()
        user.save()

        return Response(
            {
                'id': str(user.id),
                'email': user.email,
                'display_name': user.display_name,
                'public_key': user.public_key,
                'created_at': user.created_at.isoformat(),
            },
            status=status.HTTP_201_CREATED,
        )
