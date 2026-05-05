from datetime import datetime, timedelta

import jwt
from Crypto.PublicKey import RSA
from django.conf import settings

from auth_module.models import User


def make_crypto_user(email, display_name):
    rsa_key = RSA.generate(2048)
    private_key_pem = rsa_key.export_key().decode('utf-8')
    public_key_pem = rsa_key.publickey().export_key().decode('utf-8')

    user = User(
        email=email,
        display_name=display_name,
        password_hash='irrelevant-password-hash',
        public_key=public_key_pem,
        encrypted_private_key='c2FsdA==:bm9uY2U=:Y2lwaGVydGV4dA==',
    )
    user.set_unusable_password()
    user.save()

    return user, private_key_pem


def make_access_token(user, *, token_type='access', expires_delta=timedelta(hours=1)):
    now = datetime.utcnow()
    payload = {
        'user_id': str(user.id),
        'email': user.email,
        'exp': now + expires_delta,
        'iat': now,
        'type': token_type,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')


def make_token_without_user_id(user, *, token_type='access', expires_delta=timedelta(hours=1)):
    now = datetime.utcnow()
    payload = {
        'email': user.email,
        'exp': now + expires_delta,
        'iat': now,
        'type': token_type,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
