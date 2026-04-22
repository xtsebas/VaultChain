from rest_framework.test import APITestCase
from rest_framework import status
from argon2 import PasswordHasher

from auth_module.models import User

REGISTER_URL = '/auth/register'


def make_user(email='user@test.com', display_name='Test User', password='securepass123'):
    ph = PasswordHasher()
    user = User(
        email=email,
        display_name=display_name,
        password_hash=ph.hash(password),
        public_key='-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfake==\n-----END PUBLIC KEY-----\n',
        encrypted_private_key='c2FsdA==:bm9uY2U=:Y2lwaGVydGV4dA==',
    )
    user.set_unusable_password()
    user.save()
    return user


class RegisterSuccessTest(APITestCase):
    def test_returns_201_with_expected_fields(self):
        payload = {
            'email': 'new@example.com',
            'display_name': 'New User',
            'password': 'strongpass1',
        }
        response = self.client.post(REGISTER_URL, payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        data = response.json()
        self.assertIn('id', data)
        self.assertIn('public_key', data)
        self.assertIn('created_at', data)
        self.assertEqual(data['email'], payload['email'])
        self.assertEqual(data['display_name'], payload['display_name'])

    def test_sensitive_fields_not_exposed(self):
        payload = {
            'email': 'safe@example.com',
            'display_name': 'Safe User',
            'password': 'strongpass1',
        }
        response = self.client.post(REGISTER_URL, payload, format='json')
        data = response.json()
        self.assertNotIn('password_hash', data)
        self.assertNotIn('encrypted_private_key', data)

    def test_persists_user_in_db(self):
        payload = {
            'email': 'persist@example.com',
            'display_name': 'Persist User',
            'password': 'strongpass1',
        }
        self.client.post(REGISTER_URL, payload, format='json')
        self.assertTrue(User.objects.filter(email=payload['email']).exists())

    def test_public_key_stored_in_pem_format(self):
        payload = {
            'email': 'pem@example.com',
            'display_name': 'PEM User',
            'password': 'strongpass1',
        }
        self.client.post(REGISTER_URL, payload, format='json')
        user = User.objects.get(email=payload['email'])
        self.assertTrue(user.public_key.startswith('-----BEGIN PUBLIC KEY-----'))

    def test_encrypted_private_key_has_three_parts(self):
        payload = {
            'email': 'enc@example.com',
            'display_name': 'Enc User',
            'password': 'strongpass1',
        }
        self.client.post(REGISTER_URL, payload, format='json')
        user = User.objects.get(email=payload['email'])
        parts = user.encrypted_private_key.split(':')
        self.assertEqual(len(parts), 3)


class RegisterDuplicateEmailTest(APITestCase):
    def setUp(self):
        make_user(email='duplicate@example.com')

    def test_duplicate_email_returns_409(self):
        payload = {
            'email': 'duplicate@example.com',
            'display_name': 'Another User',
            'password': 'strongpass1',
        }
        response = self.client.post(REGISTER_URL, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)

    def test_duplicate_email_does_not_create_second_user(self):
        payload = {
            'email': 'duplicate@example.com',
            'display_name': 'Another User',
            'password': 'strongpass1',
        }
        self.client.post(REGISTER_URL, payload, format='json')
        self.assertEqual(User.objects.filter(email='duplicate@example.com').count(), 1)


class RegisterValidationTest(APITestCase):
    def test_short_password_returns_400(self):
        payload = {'email': 'x@example.com', 'display_name': 'X', 'password': '123'}
        response = self.client.post(REGISTER_URL, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_email_returns_400(self):
        payload = {'display_name': 'X', 'password': 'strongpass1'}
        response = self.client.post(REGISTER_URL, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_email_format_returns_400(self):
        payload = {'email': 'not-an-email', 'display_name': 'X', 'password': 'strongpass1'}
        response = self.client.post(REGISTER_URL, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
