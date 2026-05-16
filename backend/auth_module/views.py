import io
import os
import base64
from datetime import datetime, timedelta

import jwt
import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.asymmetric import rsa, ec
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


def _get_authenticated_user(request):
    """
    Extrae y valida el JWT del header Authorization.
    Retorna (user, None) si es válido, o (None, Response de error) si falla.
    """
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None, Response(
            {'error': 'Missing or invalid Authorization header'},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None, Response({'error': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError:
        return None, Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)

    if payload.get('type') != 'access':
        return None, Response({'error': 'Invalid token type'}, status=status.HTTP_401_UNAUTHORIZED)

    user_id = payload.get('user_id')
    if not user_id:
        return None, Response({'error': 'Invalid token payload'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return None, Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    return user, None


def _issue_tokens(user):
    """Genera y retorna access y refresh JWT para el usuario."""
    now = datetime.utcnow()
    access_token = jwt.encode(
        {
            'user_id': str(user.id),
            'email': user.email,
            'exp': now + timedelta(hours=1),
            'iat': now,
            'type': 'access',
        },
        settings.SECRET_KEY,
        algorithm='HS256',
    )
    refresh_token = jwt.encode(
        {
            'user_id': str(user.id),
            'exp': now + timedelta(days=7),
            'iat': now,
            'type': 'refresh',
        },
        settings.SECRET_KEY,
        algorithm='HS256',
    )
    return access_token, refresh_token


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

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
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

        # Par de claves ECDSA P-256 para firmas digitales (separado del RSA de cifrado)
        ecdsa_private_key = ec.generate_private_key(ec.SECP256R1())
        ecdsa_public_key_pem = ecdsa_private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        ecdsa_private_key_der = ecdsa_private_key.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )

        ecdsa_salt = os.urandom(32)
        ecdsa_kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=ecdsa_salt,
            iterations=600_000,
        )
        ecdsa_derived_key = ecdsa_kdf.derive(password.encode('utf-8'))
        ecdsa_nonce = os.urandom(12)
        ecdsa_aesgcm = AESGCM(ecdsa_derived_key)
        ecdsa_ciphertext = ecdsa_aesgcm.encrypt(ecdsa_nonce, ecdsa_private_key_der, None)

        encrypted_ecdsa_private_key = ':'.join([
            base64.b64encode(ecdsa_salt).decode(),
            base64.b64encode(ecdsa_nonce).decode(),
            base64.b64encode(ecdsa_ciphertext).decode(),
        ])

        user = User(
            email=email,
            display_name=display_name,
            password_hash=password_hash,
            public_key=public_key_pem,
            encrypted_private_key=encrypted_private_key,
            ecdsa_public_key=ecdsa_public_key_pem,
            encrypted_ecdsa_private_key=encrypted_ecdsa_private_key,
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

        if user.totp_secret:
            return Response(
                {
                    'mfa_required': True,
                    'email': user.email,
                },
                status=status.HTTP_200_OK,
            )

        access_token, refresh_token = _issue_tokens(user)

        return Response(
            {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_type': 'Bearer',
                'expires_in': 3600,
                'encrypted_private_key': user.encrypted_private_key,
                'encrypted_ecdsa_private_key': user.encrypted_ecdsa_private_key,
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'display_name': user.display_name,
                }
            },
            status=status.HTTP_200_OK,
        )


class MFAEnableView(APIView):
    """
    POST /auth/mfa/enable
    Genera un secreto TOTP, lo guarda en totp_secret del usuario y retorna
    el secreto, la URI de aprovisionamiento y un QR compatible con Google Authenticator.
    Requiere JWT válido.
    """
    def post(self, request):
        user, error = _get_authenticated_user(request)
        if error:
            return error

        secret = pyotp.random_base32()
        user.totp_secret = secret
        user.save(update_fields=['totp_secret'])

        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.email,
            issuer_name='VaultChain',
        )

        qr_img = qrcode.make(provisioning_uri)
        buffer = io.BytesIO()
        qr_img.save(buffer, format='PNG')
        qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

        return Response(
            {
                'secret': secret,
                'provisioning_uri': provisioning_uri,
                'qr_code': f'data:image/png;base64,{qr_base64}',
            },
            status=status.HTTP_200_OK,
        )


class MFAVerifyView(APIView):
    """
    POST /auth/mfa/verify
    Verifica el código TOTP ingresado durante el flujo de login.
    Body: { "email": "...", "totp_code": "123456" }
    Si el código es válido emite los tokens JWT completos.
    """
    def post(self, request):
        email = request.data.get('email')
        totp_code = request.data.get('totp_code')

        if not email or not totp_code:
            return Response(
                {'error': 'email and totp_code are required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not user.totp_secret:
            return Response(
                {'error': 'MFA is not enabled for this user'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            return Response(
                {'error': 'Invalid or expired TOTP code'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        access_token, refresh_token = _issue_tokens(user)

        return Response(
            {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_type': 'Bearer',
                'expires_in': 3600,
                'encrypted_private_key': user.encrypted_private_key,
                'encrypted_ecdsa_private_key': user.encrypted_ecdsa_private_key,
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'display_name': user.display_name,
                },
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


@csrf_exempt
@require_http_methods(["GET"])
def list_users(request):
    """
    GET /auth/users/
    Lista todos los usuarios registrados (id, email, display_name).
    Usado por el frontend para seleccionar destinatarios.
    """
    users = User.objects.all().values('id', 'email', 'display_name')
    return JsonResponse({
        'users': [
            {
                'id': str(u['id']),
                'email': u['email'],
                'display_name': u['display_name'],
            }
            for u in users
        ]
    })
