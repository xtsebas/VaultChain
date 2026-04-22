import os
import base64
from datetime import datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.conf import settings

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import User
from .serializers import RegisterSerializer, LoginSerializer


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

        ph = PasswordHasher()
        password_hash = ph.hash(password)

        private_key = generate_private_key(SECP256R1())
        public_key_pem = private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        private_key_der = private_key.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )

        pbkdf2_salt = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=pbkdf2_salt,
            iterations=600_000,
        )
        derived_key = kdf.derive(password.encode('utf-8'))

        nonce = os.urandom(12)
        aesgcm = AESGCM(derived_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, private_key_der, None)

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


class LoginView(APIView):
    def post(self, request):
        """
        POST /auth/login
        Verifica el hash de la contraseña con Argon2id y emite tokens JWT.
        """
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        email = data['email']
        password = data['password']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        ph = PasswordHasher()
        try:
            ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        now = datetime.utcnow()
        access_token_payload = {
            'user_id': str(user.id),
            'email': user.email,
            'exp': now + timedelta(hours=1),
            'iat': now,
            'type': 'access',
        }
        refresh_token_payload = {
            'user_id': str(user.id),
            'exp': now + timedelta(days=7),
            'iat': now,
            'type': 'refresh',
        }

        access_token = jwt.encode(
            access_token_payload,
            settings.SECRET_KEY,
            algorithm='HS256'
        )
        refresh_token = jwt.encode(
            refresh_token_payload,
            settings.SECRET_KEY,
            algorithm='HS256'
        )

        return Response(
            {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_type': 'Bearer',
                'expires_in': 3600,
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'display_name': user.display_name,
                }
            },
            status=status.HTTP_200_OK,
        )


@csrf_exempt
@require_http_methods(["GET"])
def get_user_public_key(request, user_id):
    """
    GET /auth/users/{user_id}/key
    Retorna la llave pública del usuario en formato PEM.
    """
    try:
        user = User.objects.get(id=user_id)
        return HttpResponse(
            user.public_key,
            content_type='application/x-pem-file',
            status=200
        )
    except User.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
