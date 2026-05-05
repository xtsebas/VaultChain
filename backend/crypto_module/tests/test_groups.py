import base64
from unittest.mock import patch

from rest_framework import status
from rest_framework.test import APITestCase

from crypto_module.encryption import encrypt_message
from crypto_module.decryption import decrypt_message
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

    def test_group_message_is_created_for_multiple_recipients(self):
        group_response = self.client.post(
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

        self.assertEqual(group_response.status_code, status.HTTP_201_CREATED)
        group_id = group_response.json()['id']

        plaintext = 'Mensaje para todo el grupo'
        send_response = self.client.post(
            MESSAGES_URL,
            {'group_id': group_id, 'plaintext': plaintext},
            format='json',
        )

        self.assertEqual(send_response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(send_response.json()['message_count'], 2)

        messages = list(Message.objects.filter(group_id=group_id).order_by('recipient__email'))
        self.assertEqual(len(messages), 2)
        self.assertEqual(
            {str(message.recipient_id) for message in messages},
            {str(self.recipient_one.id), str(self.recipient_two.id)},
        )
        self.assertEqual(
            {message.ciphertext for message in messages},
            {send_response.json()['ciphertext']},
        )
        self.assertEqual(
            {message.nonce for message in messages},
            {send_response.json()['nonce']},
        )
        self.assertEqual(
            {message.auth_tag for message in messages},
            {send_response.json()['auth_tag']},
        )
        self.assertEqual(len({message.encrypted_key for message in messages}), 2)

        private_keys_by_recipient = {
            str(self.recipient_one.id): self.recipient_one_private_key,
            str(self.recipient_two.id): self.recipient_two_private_key,
        }

        for message in messages:
            decrypted = decrypt_message(
                message.ciphertext,
                message.encrypted_key,
                message.nonce,
                message.auth_tag,
                private_keys_by_recipient[str(message.recipient_id)],
            ).decode('utf-8')
            self.assertEqual(decrypted, plaintext)

    def test_group_message_returns_404_for_unknown_group(self):
        response = self.client.post(
            MESSAGES_URL,
            {'group_id': str(self.sender.id), 'plaintext': 'hola grupo'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.json()['error'], 'Group not found or has no members')

    @patch('crypto_module.views.encrypt_key_rsa_oaep', side_effect=Exception('boom'))
    def test_group_message_returns_500_when_encryption_fails(self, _mock_encrypt_key):
        group = Group.objects.create(name='Equipo')
        GroupMember.objects.create(group=group, user=self.recipient_one)

        response = self.client.post(
            MESSAGES_URL,
            {'group_id': str(group.id), 'plaintext': 'hola grupo'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.json()['error'], 'Error encrypting group message: boom')


class CryptoIntegrityTest(APITestCase):
    def test_decrypt_message_rejects_tampered_auth_tag(self):
        recipient, private_key_pem = make_crypto_user(
            email='integrity@example.com',
            display_name='Integrity',
        )
        encrypted_data = encrypt_message(
            'mensaje integro',
            recipient.public_key,
        )

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
        self.assertEqual(
            str(membership),
            f'GroupMember {recipient.id} in {group.id}',
        )
        self.assertEqual(
            str(message),
            f'Message {message.id} from {sender.id}',
        )
