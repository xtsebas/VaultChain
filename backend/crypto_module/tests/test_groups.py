import base64
from unittest.mock import patch

from rest_framework import status
from rest_framework.test import APITestCase

from crypto_module.decryption import decrypt_message
from crypto_module.encryption import (
    encrypt_message,
    generate_aes_key,
    generate_nonce,
    encrypt_aes_gcm,
    encrypt_key_rsa_oaep,
)
from crypto_module.models import Group, GroupMember, Message
from crypto_module.tests.helpers import make_access_token, make_crypto_user

GROUPS_URL = '/groups/'
MESSAGES_URL = '/messages/'


class CreateGroupTest(APITestCase):
    def setUp(self):
        self.sender, _ = make_crypto_user(
            email='owner@example.com',
            display_name='Owner',
        )
        self.recipient_one, self.recipient_one_private_key = make_crypto_user(
            email='alice@example.com',
            display_name='Alice',
        )
        self.recipient_two, self.recipient_two_private_key = make_crypto_user(
            email='bob@example.com',
            display_name='Bob',
        )
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.sender)}'
        )

    def test_group_can_be_created_with_multiple_members(self):
        response = self.client.post(
            GROUPS_URL,
            {
                'name': 'Equipo de cifrado',
                'member_ids': [
                    str(self.recipient_one.id),
                    str(self.recipient_two.id),
                ],
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.json()['name'], 'Equipo de cifrado')
        self.assertEqual(len(response.json()['members']), 2)
        # La respuesta ahora incluye public_key de cada miembro
        for member in response.json()['members']:
            self.assertIn('public_key', member)

        group = Group.objects.get(id=response.json()['id'])
        self.assertEqual(group.name, 'Equipo de cifrado')
        self.assertEqual(GroupMember.objects.filter(group=group).count(), 2)

    def test_group_creation_returns_404_for_unknown_members(self):
        ghost_user, _ = make_crypto_user(
            email='ghost-member@example.com',
            display_name='Ghost Member',
        )
        ghost_id = str(ghost_user.id)
        ghost_user.delete()

        response = self.client.post(
            GROUPS_URL,
            {'name': 'Equipo', 'member_ids': [ghost_id]},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.json()['error'], 'Users not found')
        self.assertEqual(response.json()['missing_ids'], [ghost_id])

    def test_group_creation_rejects_empty_member_list(self):
        response = self.client.post(
            GROUPS_URL,
            {'name': 'Equipo', 'member_ids': []},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Ensure this field has at least 1 elements.', response.json()['member_ids'][0])

    def test_group_creation_requires_authorization(self):
        self.client.credentials()

        response = self.client.post(
            GROUPS_URL,
            {'name': 'Equipo', 'member_ids': [str(self.recipient_one.id)]},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'Missing or invalid Authorization header')


class GroupMessageFlowTest(APITestCase):
    def setUp(self):
        self.sender, self.sender_private_key = make_crypto_user(
            email='owner@example.com',
            display_name='Owner',
        )
        self.recipient_one, self.recipient_one_private_key = make_crypto_user(
            email='alice@example.com',
            display_name='Alice',
        )
        self.recipient_two, self.recipient_two_private_key = make_crypto_user(
            email='bob@example.com',
            display_name='Bob',
        )
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.sender)}'
        )

    def _create_group(self):
        resp = self.client.post(
            GROUPS_URL,
            {
                'name': 'Equipo de cifrado',
                'member_ids': [
                    str(self.sender.id),
                    str(self.recipient_one.id),
                    str(self.recipient_two.id),
                ],
            },
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        return resp.json()['id']

    def _build_group_payload(self, plaintext, group_id):
        """Simula el cifrado grupal que haría el cliente (E2E).
        El sender cifra la clave AES para cada miembro del grupo, incluyéndose a sí mismo.
        """
        aes_key = generate_aes_key()
        nonce = generate_nonce()
        ciphertext_bytes, auth_tag_bytes = encrypt_aes_gcm(
            plaintext.encode('utf-8'), aes_key, nonce
        )

        return {
            'group_id': group_id,
            'ciphertext': base64.b64encode(ciphertext_bytes).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'auth_tag': base64.b64encode(auth_tag_bytes).decode(),
            'encrypted_keys': [
                {
                    'user_id': str(self.sender.id),
                    'encrypted_key': base64.b64encode(
                        encrypt_key_rsa_oaep(aes_key, self.sender.public_key)
                    ).decode(),
                },
                {
                    'user_id': str(self.recipient_one.id),
                    'encrypted_key': base64.b64encode(
                        encrypt_key_rsa_oaep(aes_key, self.recipient_one.public_key)
                    ).decode(),
                },
                {
                    'user_id': str(self.recipient_two.id),
                    'encrypted_key': base64.b64encode(
                        encrypt_key_rsa_oaep(aes_key, self.recipient_two.public_key)
                    ).decode(),
                },
            ],
        }

    def test_group_message_is_created_for_multiple_recipients(self):
        group_id = self._create_group()
        plaintext = 'Mensaje para todo el grupo'

        # Cliente cifra: un AES key, ciphertext único, encrypted_key por miembro
        payload = self._build_group_payload(plaintext, group_id)
        send_response = self.client.post(MESSAGES_URL, payload, format='json')

        self.assertEqual(send_response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(send_response.json()['message_count'], 3)

        messages = list(Message.objects.filter(group_id=group_id).order_by('recipient__email'))
        self.assertEqual(len(messages), 3)
        self.assertEqual(
            {str(message.recipient_id) for message in messages},
            {str(self.sender.id), str(self.recipient_one.id), str(self.recipient_two.id)},
        )
        # Mismo ciphertext, mismo nonce, mismo auth_tag para todos
        self.assertEqual(len({message.ciphertext for message in messages}), 1)
        self.assertEqual(len({message.nonce for message in messages}), 1)
        self.assertEqual(len({message.auth_tag for message in messages}), 1)
        # Encrypted key diferente por miembro
        self.assertEqual(len({message.encrypted_key for message in messages}), 3)

        # Verificación E2E: cada miembro descifra con su llave privada
        private_keys = {
            str(self.sender.id): self.sender_private_key,
            str(self.recipient_one.id): self.recipient_one_private_key,
            str(self.recipient_two.id): self.recipient_two_private_key,
        }
        for message in messages:
            decrypted = decrypt_message(
                message.ciphertext,
                message.encrypted_key,
                message.nonce,
                message.auth_tag,
                private_keys[str(message.recipient_id)],
            ).decode('utf-8')
            self.assertEqual(decrypted, plaintext)

    def test_group_message_returns_404_for_unknown_group(self):
        fake_group_id = str(self.sender.id)  # UUID que no es un grupo
        aes_key = generate_aes_key()
        nonce = generate_nonce()
        ciphertext_bytes, auth_tag_bytes = encrypt_aes_gcm(b'hola', aes_key, nonce)

        response = self.client.post(
            MESSAGES_URL,
            {
                'group_id': fake_group_id,
                'ciphertext': base64.b64encode(ciphertext_bytes).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'auth_tag': base64.b64encode(auth_tag_bytes).decode(),
                'encrypted_keys': [
                    {
                        'user_id': str(self.recipient_one.id),
                        'encrypted_key': base64.b64encode(
                            encrypt_key_rsa_oaep(aes_key, self.recipient_one.public_key)
                        ).decode(),
                    }
                ],
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.json()['error'], 'You are not a member of this group')

    @patch('crypto_module.views.Message.objects.create', side_effect=Exception('boom'))
    def test_group_message_returns_500_when_storage_fails(self, _mock_create):
        group = Group.objects.create(name='Equipo')
        GroupMember.objects.create(group=group, user=self.sender)
        GroupMember.objects.create(group=group, user=self.recipient_one)

        aes_key = generate_aes_key()
        nonce = generate_nonce()
        ciphertext_bytes, auth_tag_bytes = encrypt_aes_gcm(b'hola', aes_key, nonce)

        response = self.client.post(
            MESSAGES_URL,
            {
                'group_id': str(group.id),
                'ciphertext': base64.b64encode(ciphertext_bytes).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'auth_tag': base64.b64encode(auth_tag_bytes).decode(),
                'encrypted_keys': [
                    {
                        'user_id': str(self.recipient_one.id),
                        'encrypted_key': base64.b64encode(
                            encrypt_key_rsa_oaep(aes_key, self.recipient_one.public_key)
                        ).decode(),
                    }
                ],
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('Error storing group message', response.json()['error'])


class CryptoIntegrityTest(APITestCase):
    def test_decrypt_message_rejects_tampered_auth_tag(self):
        recipient, private_key_pem = make_crypto_user(
            email='integrity@example.com',
            display_name='Integrity',
        )
        encrypted_data = encrypt_message('mensaje integro', recipient.public_key)

        auth_tag_bytes = bytearray(base64.b64decode(encrypted_data['auth_tag']))
        auth_tag_bytes[0] ^= 1
        tampered_auth_tag = base64.b64encode(bytes(auth_tag_bytes)).decode('utf-8')

        with self.assertRaises(ValueError):
            decrypt_message(
                encrypted_data['ciphertext'],
                encrypted_data['encrypted_key'],
                encrypted_data['nonce'],
                tampered_auth_tag,
                private_key_pem,
            )


class CryptoModelTest(APITestCase):
    def test_model_string_representations_are_human_readable(self):
        sender, _ = make_crypto_user(
            email='model-sender@example.com',
            display_name='Model Sender',
        )
        recipient, _ = make_crypto_user(
            email='model-recipient@example.com',
            display_name='Model Recipient',
        )
        group = Group.objects.create(name='Modelo')
        membership = GroupMember.objects.create(group=group, user=recipient)
        message = Message.objects.create(
            sender=sender,
            recipient=recipient,
            ciphertext='ciphertext',
            encrypted_key='encrypted-key',
            nonce='nonce',
            auth_tag='auth-tag',
        )

        self.assertEqual(str(group), 'Modelo')
        self.assertEqual(str(membership), f'GroupMember {recipient.id} in {group.id}')
        self.assertEqual(str(message), f'Message {message.id} from {sender.id}')
