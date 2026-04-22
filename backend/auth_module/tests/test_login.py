from rest_framework.test import APITestCase
from rest_framework import status
from argon2 import PasswordHasher

from auth_module.models import User

LOGIN_URL = '/auth/login'


def make_user(email='login@test.com', password='securepass123'):
    ph = PasswordHasher()
    user = User(
        email=email,
        display_name='Login User',
        password_hash=ph.hash(password),
        public_key='-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfake==\n-----END PUBLIC KEY-----\n',
        encrypted_private_key='c2FsdA==:bm9uY2U=:Y2lwaGVydGV4dA==',
    )
    user.set_unusable_password()
    user.save()
    return user


class LoginSuccessTest(APITestCase):
    def setUp(self):
        self.password = 'securepass123'
        self.user = make_user(email='ok@example.com', password=self.password)

    def test_correct_credentials_return_200(self):
        response = self.client.post(
            LOGIN_URL, {'email': 'ok@example.com', 'password': self.password}, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_response_contains_access_and_refresh_tokens(self):
        response = self.client.post(
            LOGIN_URL, {'email': 'ok@example.com', 'password': self.password}, format='json'
        )
        data = response.json()
        self.assertIn('access_token', data)
        self.assertIn('refresh_token', data)
        self.assertEqual(data['token_type'], 'Bearer')
        self.assertEqual(data['expires_in'], 3600)

    def test_response_includes_user_info_without_sensitive_fields(self):
        response = self.client.post(
            LOGIN_URL, {'email': 'ok@example.com', 'password': self.password}, format='json'
        )
        data = response.json()
        self.assertEqual(data['user']['email'], 'ok@example.com')
        self.assertIn('id', data['user'])
        self.assertNotIn('password_hash', data['user'])
        self.assertNotIn('encrypted_private_key', data['user'])


class LoginFailureTest(APITestCase):
    def setUp(self):
        self.user = make_user(email='fail@example.com', password='correctpass1')

    def test_wrong_password_returns_401(self):
        response = self.client.post(
            LOGIN_URL, {'email': 'fail@example.com', 'password': 'wrongpassword'}, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_nonexistent_email_returns_401(self):
        response = self.client.post(
            LOGIN_URL, {'email': 'ghost@example.com', 'password': 'anypassword'}, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_error_message_is_generic(self):
        response = self.client.post(
            LOGIN_URL, {'email': 'fail@example.com', 'password': 'wrongpassword'}, format='json'
        )
        self.assertEqual(response.json()['error'], 'Invalid credentials')

    def test_missing_password_returns_400(self):
        response = self.client.post(
            LOGIN_URL, {'email': 'fail@example.com'}, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
