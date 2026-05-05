from datetime import timedelta
from unittest.mock import patch

from rest_framework import status
from rest_framework.test import APITestCase
from django.utils import timezone

from crypto_module.decryption import decrypt_message
from crypto_module.models import Message
from crypto_module.tests.helpers import (
    make_access_token,
    make_crypto_user,
    make_token_without_user_id,
)

MESSAGES_URL = '/messages/'


class SendMessageFlowTest(APITestCase):
    def setUp(self):
        self.sender, _ = make_crypto_user(
            email='sender@example.com',
            display_name='Sender',
        )
        self.recipient, self.recipient_private_key = make_crypto_user(
            email='recipient@example.com',
            display_name='Recipient',
        )
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.sender)}'
        )

    def test_direct_message_can_be_decrypted_end_to_end(self):
        plaintext = 'Mensaje secreto end-to-end'

        response = self.client.post(
            MESSAGES_URL,
            {'recipient_id': str(self.recipient.id), 'plaintext': plaintext},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        message = Message.objects.get(id=response.json()['id'])
        decrypted = decrypt_message(
            message.ciphertext,
            message.encrypted_key,
            message.nonce,
            message.auth_tag,
            self.recipient_private_key,
        ).decode('utf-8')

        self.assertEqual(decrypted, plaintext)
        self.assertEqual(message.sender_id, self.sender.id)
        self.assertEqual(message.recipient_id, self.recipient.id)
        self.assertIsNone(message.group_id)

    def test_each_send_uses_a_unique_nonce(self):
        payload = {
            'recipient_id': str(self.recipient.id),
            'plaintext': 'Mismo contenido, distinto envio',
        }

        first_response = self.client.post(MESSAGES_URL, payload, format='json')
        second_response = self.client.post(MESSAGES_URL, payload, format='json')

        self.assertEqual(first_response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(second_response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(first_response.json()['nonce'], second_response.json()['nonce'])

        stored_nonces = list(
            Message.objects.order_by('created_at').values_list('nonce', flat=True)
        )
        self.assertEqual(len(stored_nonces), 2)
        self.assertEqual(len(set(stored_nonces)), 2)

    @patch('crypto_module.views.encrypt_message', side_effect=Exception('boom'))
    def test_direct_message_returns_500_when_encryption_fails(self, _mock_encrypt_message):
        response = self.client.post(
            MESSAGES_URL,
            {'recipient_id': str(self.recipient.id), 'plaintext': 'irrelevant'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.json()['error'], 'Error encrypting message: boom')


class SendMessageValidationTest(APITestCase):
    def setUp(self):
        self.sender, _ = make_crypto_user(
            email='validator@example.com',
            display_name='Validator',
        )
        self.recipient, _ = make_crypto_user(
            email='target@example.com',
            display_name='Target',
        )

    def test_missing_authorization_header_returns_401(self):
        response = self.client.post(
            MESSAGES_URL,
            {'recipient_id': str(self.recipient.id), 'plaintext': 'hola'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'Missing or invalid Authorization header')

    def test_expired_token_returns_401(self):
        expired_token = make_access_token(
            self.sender,
            expires_delta=timedelta(hours=-1),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {expired_token}')

        response = self.client.post(
            MESSAGES_URL,
            {'recipient_id': str(self.recipient.id), 'plaintext': 'hola'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'Token has expired')

    def test_refresh_token_type_is_rejected(self):
        refresh_token = make_access_token(self.sender, token_type='refresh')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh_token}')

        response = self.client.post(
            MESSAGES_URL,
            {'recipient_id': str(self.recipient.id), 'plaintext': 'hola'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'Invalid token type')

    def test_malformed_token_is_rejected(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalid.token.value')

        response = self.client.post(
            MESSAGES_URL,
            {'recipient_id': str(self.recipient.id), 'plaintext': 'hola'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'Invalid token')

    def test_token_without_user_id_is_rejected(self):
        token = make_token_without_user_id(self.sender)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.post(
            MESSAGES_URL,
            {'recipient_id': str(self.recipient.id), 'plaintext': 'hola'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'Invalid token payload')

    def test_unknown_user_in_token_is_rejected(self):
        ghost_user, _ = make_crypto_user(
            email='ghost@example.com',
            display_name='Ghost',
        )
        token = make_access_token(ghost_user)
        ghost_user.delete()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.post(
            MESSAGES_URL,
            {'recipient_id': str(self.recipient.id), 'plaintext': 'hola'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'User not found')

    def test_recipient_id_or_group_id_is_required(self):
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.sender)}'
        )

        response = self.client.post(
            MESSAGES_URL,
            {'plaintext': 'hola'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn(
            'Either recipient_id or group_id is required.',
            response.json()['non_field_errors'],
        )

    def test_recipient_id_and_group_id_cannot_be_sent_together(self):
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.sender)}'
        )

        response = self.client.post(
            MESSAGES_URL,
            {
                'recipient_id': str(self.recipient.id),
                'group_id': str(self.sender.id),
                'plaintext': 'hola',
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn(
            'Provide either recipient_id or group_id, not both.',
            response.json()['non_field_errors'],
        )

    def test_unknown_recipient_returns_404(self):
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.sender)}'
        )
        ghost_user, _ = make_crypto_user(
            email='ghost-recipient@example.com',
            display_name='Ghost Recipient',
        )
        ghost_id = str(ghost_user.id)
        ghost_user.delete()

        response = self.client.post(
            MESSAGES_URL,
            {'recipient_id': ghost_id, 'plaintext': 'hola'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.json()['error'], 'Recipient not found')


class GetUserMessagesTest(APITestCase):
    def setUp(self):
        self.sender, _ = make_crypto_user(
            email='author@example.com',
            display_name='Author',
        )
        self.recipient, _ = make_crypto_user(
            email='reader@example.com',
            display_name='Reader',
        )
        self.other_user, _ = make_crypto_user(
            email='other@example.com',
            display_name='Other',
        )

    def test_user_can_fetch_only_own_messages_in_descending_order(self):
        older = Message.objects.create(
            sender=self.sender,
            recipient=self.recipient,
            group_id=None,
            ciphertext='cipher-old',
            encrypted_key='key-old',
            nonce='nonce-old',
            auth_tag='tag-old',
        )
        newer = Message.objects.create(
            sender=self.other_user,
            recipient=self.recipient,
            group_id=self.sender.id,
            ciphertext='cipher-new',
            encrypted_key='key-new',
            nonce='nonce-new',
            auth_tag='tag-new',
        )
        Message.objects.create(
            sender=self.sender,
            recipient=self.other_user,
            group_id=None,
            ciphertext='cipher-ignored',
            encrypted_key='key-ignored',
            nonce='nonce-ignored',
            auth_tag='tag-ignored',
        )

        older.created_at = timezone.now() - timedelta(minutes=10)
        newer.created_at = timezone.now()
        older.save(update_fields=['created_at'])
        newer.save(update_fields=['created_at'])

        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.recipient)}'
        )
        response = self.client.get(f'{MESSAGES_URL}{self.recipient.id}')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        messages = response.json()['messages']
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]['id'], str(newer.id))
        self.assertEqual(messages[1]['id'], str(older.id))
        self.assertEqual(messages[0]['group_id'], str(self.sender.id))
        self.assertIsNone(messages[1]['group_id'])
        self.assertIsNone(messages[0]['signature'])

    def test_user_cannot_fetch_another_users_messages(self):
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.sender)}'
        )

        response = self.client.get(f'{MESSAGES_URL}{self.recipient.id}')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.json()['error'], 'You can only access your own messages')

    def test_get_user_messages_requires_authorization(self):
        response = self.client.get(f'{MESSAGES_URL}{self.recipient.id}')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'Missing or invalid Authorization header')

    def test_get_user_messages_rejects_expired_token(self):
        expired_token = make_access_token(
            self.recipient,
            expires_delta=timedelta(hours=-1),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {expired_token}')

        response = self.client.get(f'{MESSAGES_URL}{self.recipient.id}')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'Token has expired')

    def test_get_user_messages_rejects_invalid_token_type(self):
        refresh_token = make_access_token(self.recipient, token_type='refresh')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh_token}')

        response = self.client.get(f'{MESSAGES_URL}{self.recipient.id}')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'Invalid token type')

    def test_get_user_messages_rejects_token_without_user_id(self):
        token = make_token_without_user_id(self.recipient)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.get(f'{MESSAGES_URL}{self.recipient.id}')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'Invalid token payload')

    def test_get_user_messages_rejects_unknown_user(self):
        ghost_user, _ = make_crypto_user(
            email='ghost-reader@example.com',
            display_name='Ghost Reader',
        )
        token = make_access_token(ghost_user)
        ghost_user.delete()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.get(f'{MESSAGES_URL}{self.recipient.id}')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'User not found')

    def test_get_user_messages_rejects_malformed_token(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalid.token.value')

        response = self.client.get(f'{MESSAGES_URL}{self.recipient.id}')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'Invalid token')

    @patch('crypto_module.views.Message.objects.filter', side_effect=Exception('boom'))
    def test_get_user_messages_returns_500_when_query_fails(self, _mock_filter):
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.recipient)}'
        )

        response = self.client.get(f'{MESSAGES_URL}{self.recipient.id}')

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.json()['error'], 'boom')
