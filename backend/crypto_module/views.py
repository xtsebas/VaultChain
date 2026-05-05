import base64

import jwt
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from auth_module.models import User
from .models import Group, GroupMember, Message
from .decorators import jwt_required
from .serializers import SendMessageSerializer, CreateGroupSerializer, MessageResponseSerializer
from .encryption import encrypt_message, generate_aes_key, generate_nonce, encrypt_aes_gcm, encrypt_key_rsa_oaep


def _authenticate_request(request):
    """
    Extrae y valida el JWT del header Authorization.
    Retorna (sender, None) si es válido, o (None, Response de error) si falla.
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
        sender = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return None, Response({'error': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)

    return sender, None


class SendMessageView(APIView):
    @csrf_exempt
    def post(self, request):
        """
        POST /messages/
        Envía un mensaje cifrado. Acepta recipient_id (directo) o group_id (grupal).
        """
        sender, error = _authenticate_request(request)
        if error:
            return error

        serializer = SendMessageSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        plaintext = data['plaintext']

        if data.get('group_id'):
            return self._send_group_message(sender, data['group_id'], plaintext)

        return self._send_direct_message(sender, data['recipient_id'], plaintext)

    def _send_direct_message(self, sender, recipient_id, plaintext):
        try:
            recipient = User.objects.get(id=recipient_id)
        except User.DoesNotExist:
            return Response({'error': 'Recipient not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            encrypted_data = encrypt_message(plaintext, recipient.public_key)
            message = Message.objects.create(
                sender=sender,
                recipient=recipient,
                ciphertext=encrypted_data['ciphertext'],
                encrypted_key=encrypted_data['encrypted_key'],
                nonce=encrypted_data['nonce'],
                auth_tag=encrypted_data['auth_tag'],
            )
        except Exception as e:
            return Response(
                {'error': f'Error encrypting message: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {
                'id': str(message.id),
                'sender_id': str(message.sender.id),
                'recipient_id': str(message.recipient.id),
                'ciphertext': message.ciphertext,
                'encrypted_key': message.encrypted_key,
                'nonce': message.nonce,
                'auth_tag': message.auth_tag,
                'created_at': message.created_at.isoformat(),
            },
            status=status.HTTP_201_CREATED,
        )

    def _send_group_message(self, sender, group_id, plaintext):
        members = (
            GroupMember.objects
            .filter(group_id=group_id)
            .select_related('user')
        )
        if not members.exists():
            return Response(
                {'error': 'Group not found or has no members'},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            # Una sola clave AES efímera y nonce para todos los miembros
            aes_key = generate_aes_key()
            nonce = generate_nonce()
            ciphertext_bytes, auth_tag_bytes = encrypt_aes_gcm(
                plaintext.encode('utf-8'), aes_key, nonce
            )

            ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode()
            nonce_b64 = base64.b64encode(nonce).decode()
            auth_tag_b64 = base64.b64encode(auth_tag_bytes).decode()

            # Un Message por miembro con su propia encrypted_key
            messages = []
            for member in members:
                encrypted_key_b64 = base64.b64encode(
                    encrypt_key_rsa_oaep(aes_key, member.user.public_key)
                ).decode()

                msg = Message.objects.create(
                    sender=sender,
                    recipient=member.user,
                    group_id=group_id,
                    ciphertext=ciphertext_b64,
                    encrypted_key=encrypted_key_b64,
                    nonce=nonce_b64,
                    auth_tag=auth_tag_b64,
                )
                messages.append(msg)

        except Exception as e:
            return Response(
                {'error': f'Error encrypting group message: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {
                'group_id': str(group_id),
                'message_count': len(messages),
                'ciphertext': ciphertext_b64,
                'nonce': nonce_b64,
                'auth_tag': auth_tag_b64,
                'created_at': messages[0].created_at.isoformat(),
            },
            status=status.HTTP_201_CREATED,
        )


class CreateGroupView(APIView):
    def post(self, request):
        """
        POST /groups/
        Crea un grupo con los miembros indicados.
        """
        sender, error = _authenticate_request(request)
        if error:
            return error

        serializer = CreateGroupSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        member_ids = data['member_ids']

        # Verificar que todos los usuarios existen antes de crear el grupo
        users = list(User.objects.filter(id__in=member_ids))
        found_ids = {str(u.id) for u in users}
        missing = [str(mid) for mid in member_ids if str(mid) not in found_ids]
        if missing:
            return Response(
                {'error': 'Users not found', 'missing_ids': missing},
                status=status.HTTP_404_NOT_FOUND,
            )

        group = Group.objects.create(name=data['name'])

        GroupMember.objects.bulk_create([
            GroupMember(group=group, user=user)
            for user in users
        ])

        return Response(
            {
                'id': str(group.id),
                'name': group.name,
                'created_at': group.created_at.isoformat(),
                'members': [
                    {'id': str(u.id), 'display_name': u.display_name, 'email': u.email}
                    for u in users
                ],
            },
            status=status.HTTP_201_CREATED,
        )


@csrf_exempt
@require_http_methods(["GET"])
@jwt_required
def get_user_messages(request, user_id):
    """
    GET /messages/{user_id}
    Obtiene todos los mensajes recibidos por un usuario.
    """
    if str(request.user.id) != str(user_id):
        return JsonResponse(
            {'error': 'You can only access your own messages'},
            status=403,
        )

    try:
        messages = Message.objects.filter(recipient_id=user_id).order_by('-created_at')

        messages_data = [
            {
                'id': str(msg.id),
                'sender_id': str(msg.sender.id),
                'recipient_id': str(msg.recipient.id),
                'group_id': str(msg.group_id) if msg.group_id else None,
                'ciphertext': msg.ciphertext,
                'encrypted_key': msg.encrypted_key,
                'nonce': msg.nonce,
                'auth_tag': msg.auth_tag,
                'signature': msg.signature,
                'created_at': msg.created_at.isoformat(),
            }
            for msg in messages
        ]

        return JsonResponse({'messages': messages_data}, status=200)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
