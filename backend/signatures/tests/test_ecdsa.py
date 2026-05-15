"""
Tests — Firmas Digitales ECDSA.

Cubre:
  1. Firma ECDSA correcta y verificación exitosa (criterio 1 y 2 de rúbrica)
  2. Detección y alerta de firma inválida (criterio 3 de rúbrica)
  3. Endpoint POST /signatures/verify/ con firma correcta e incorrecta
"""
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APITestCase

from crypto_module.models import Message
from crypto_module.tests.helpers import make_access_token
from signatures.ecdsa_utils import sign_message, verify_signature
from signatures.tests.helpers import generate_ecdsa_pair, make_ecdsa_user


VERIFY_URL = '/signatures/verify/'


# ── 1. Firma correcta y verificación exitosa ─────────────────────────────────

class ECDSASignAndVerifyTest(TestCase):
    """Criterios 1 y 2: firma ECDSA correcta sobre el hash del mensaje y verificación."""

    def setUp(self):
        self.private_pem, self.public_pem = generate_ecdsa_pair()
        self.plaintext = b'Mensaje de auditoria VaultChain'

    def test_sign_returns_nonempty_base64_string(self):
        """sign_message() retorna una cadena base64 no vacía."""
        sig = sign_message(self.plaintext, self.private_pem)
        self.assertIsInstance(sig, str)
        self.assertGreater(len(sig), 0)

    def test_valid_signature_is_verified(self):
        """Una firma producida con la clave privada es aceptada por verify_signature()."""
        sig = sign_message(self.plaintext, self.private_pem)
        self.assertTrue(verify_signature(self.plaintext, sig, self.public_pem))

    def test_sign_verify_roundtrip_with_multiple_messages(self):
        """El par firma/verifica funciona para distintos contenidos de texto."""
        for plaintext in [b'hola', b'Ministerio de Finanzas', b'x' * 512]:
            with self.subTest(plaintext=plaintext):
                sig = sign_message(plaintext, self.private_pem)
                self.assertTrue(verify_signature(plaintext, sig, self.public_pem))

    def test_different_keys_produce_different_signatures(self):
        """Dos pares de claves distintos generan firmas distintas para el mismo mensaje."""
        private_pem2, _ = generate_ecdsa_pair()
        sig1 = sign_message(self.plaintext, self.private_pem)
        sig2 = sign_message(self.plaintext, private_pem2)
        self.assertNotEqual(sig1, sig2)


# ── 2. Detección y alerta de firma inválida ───────────────────────────────────

class InvalidSignatureDetectionTest(TestCase):
    """Criterio 3: detección y alerta de firma inválida."""

    def setUp(self):
        self.private_pem, self.public_pem = generate_ecdsa_pair()
        self.plaintext = b'Contenido original del mensaje'

    def test_tampered_plaintext_is_rejected(self):
        """Si el plaintext cambia tras firmar, verify_signature devuelve False."""
        sig = sign_message(self.plaintext, self.private_pem)
        tampered = self.plaintext + b'_adulterado'
        self.assertFalse(verify_signature(tampered, sig, self.public_pem))

    def test_wrong_public_key_is_rejected(self):
        """Una clave pública ajena no puede verificar la firma."""
        sig = sign_message(self.plaintext, self.private_pem)
        _, other_public_pem = generate_ecdsa_pair()
        self.assertFalse(verify_signature(self.plaintext, sig, other_public_pem))

    def test_garbage_signature_returns_false(self):
        """Una firma arbitraria/corrupta retorna False sin lanzar excepción."""
        self.assertFalse(
            verify_signature(self.plaintext, 'esto-no-es-firma-valida==', self.public_pem)
        )

    def test_empty_signature_returns_false(self):
        """Una firma vacía retorna False."""
        self.assertFalse(verify_signature(self.plaintext, '', self.public_pem))


# ── 3. Endpoint POST /signatures/verify/ ─────────────────────────────────────

class SignatureVerifyEndpointTest(APITestCase):
    """Tests de integración del endpoint POST /signatures/verify/."""

    def _make_message(self, sender, recipient, plaintext, sign_with_private_pem):
        sig = sign_message(plaintext.encode('utf-8'), sign_with_private_pem)
        return Message.objects.create(
            sender=sender,
            recipient=recipient,
            ciphertext='ciphertext',
            encrypted_key='key',
            nonce='nonce00000000000000000',
            auth_tag='tag000000000000000000',
            signature=sig,
        )

    def test_endpoint_returns_verified_true_for_correct_signature(self):
        """verified=True cuando la firma corresponde exactamente al plaintext."""
        sender, sender_ecdsa_private = make_ecdsa_user('ep_s@test.com', 'Sender')
        recipient, _ = make_ecdsa_user('ep_r@test.com', 'Recipient')

        plaintext = 'Mensaje auténtico del remitente'
        message = self._make_message(sender, recipient, plaintext, sender_ecdsa_private)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {make_access_token(recipient)}')
        resp = self.client.post(
            VERIFY_URL,
            {'message_id': str(message.id), 'plaintext': plaintext},
            format='json',
        )

        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertTrue(resp.json()['verified'])

    def test_endpoint_returns_verified_false_for_wrong_plaintext(self):
        """verified=False cuando el plaintext no corresponde a la firma — alerta al usuario."""
        sender, sender_ecdsa_private = make_ecdsa_user('ep_ws@test.com', 'Sender')
        recipient, _ = make_ecdsa_user('ep_wr@test.com', 'Recipient')

        message = self._make_message(sender, recipient, 'Texto firmado', sender_ecdsa_private)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {make_access_token(recipient)}')
        resp = self.client.post(
            VERIFY_URL,
            {'message_id': str(message.id), 'plaintext': 'Texto diferente adulterado'},
            format='json',
        )

        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertFalse(resp.json()['verified'])

    def test_endpoint_requires_authentication(self):
        """El endpoint rechaza peticiones sin JWT."""
        resp = self.client.post(VERIFY_URL, {}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
