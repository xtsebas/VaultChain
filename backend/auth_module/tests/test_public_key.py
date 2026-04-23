from rest_framework.test import APITestCase
from argon2 import PasswordHasher

from auth_module.models import User

FAKE_PUBLIC_KEY = (
    '-----BEGIN PUBLIC KEY-----\n'
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfakeKeyData==\n'
    '-----END PUBLIC KEY-----\n'
)


def make_user(email='key@test.com'):
    ph = PasswordHasher()
    user = User(
        email=email,
        display_name='Key User',
        password_hash=ph.hash('somepassword1'),
        public_key=FAKE_PUBLIC_KEY,
        encrypted_private_key='c2FsdA==:bm9uY2U=:Y2lwaGVydGV4dA==',
    )
    user.set_unusable_password()
    user.save()
    return user


class PublicKeyTest(APITestCase):
    def setUp(self):
        self.user = make_user()

    def test_existing_user_returns_200(self):
        response = self.client.get(f'/auth/users/{self.user.id}/key')
        self.assertEqual(response.status_code, 200)

    def test_response_contains_pem_content(self):
        response = self.client.get(f'/auth/users/{self.user.id}/key')
        self.assertIn(b'BEGIN PUBLIC KEY', response.content)
        self.assertIn(b'END PUBLIC KEY', response.content)

    def test_content_type_is_pem(self):
        response = self.client.get(f'/auth/users/{self.user.id}/key')
        self.assertIn('application/x-pem-file', response.get('Content-Type', ''))

    def test_nonexistent_user_returns_404(self):
        response = self.client.get('/auth/users/00000000-0000-0000-0000-000000000000/key')
        self.assertEqual(response.status_code, 404)

    def test_returned_key_matches_stored_key(self):
        response = self.client.get(f'/auth/users/{self.user.id}/key')
        self.assertEqual(response.content.decode(), FAKE_PUBLIC_KEY)
