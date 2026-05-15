import base64
import json
import jwt

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from auth_module.models import User
from .encryption import encrypt_message, generate_aes_key, generate_nonce, encrypt_aes_gcm, encrypt_key_rsa_oaep
from .models import Group, GroupMember, Message
from .decorators import jwt_required
from .serializers import SendMessageSerializer, CreateGroupSerializer
from signatures.ecdsa_utils import verify_signature
from blockchain.chain import append_block

import logging
logger = logging.getLogger(__name__)


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
        El cliente firma el SHA-256(plaintext) con ECDSA y envia el plaintext + firma.
        El servidor cifra con RSA-OAEP + AES-256-GCM y guarda la firma.

        Payload directo:  { recipient_id, plaintext, signature }
        Payload grupal:   { group_id, plaintext, signature }
        """
        sender, error = _authenticate_request(request)
        if error:
            return error

        serializer = SendMessageSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data

        if data.get('group_id'):
            return self._send_group_message(sender, data['group_id'], data)

        return self._send_direct_message(sender, data['recipient_id'], data)

    def _send_direct_message(self, sender, recipient_id, data):
        try:
            recipient = User.objects.get(id=recipient_id)
        except User.DoesNotExist:
            return Response({'error': 'Recipient not found'}, status=status.HTTP_404_NOT_FOUND)

        if not recipient.public_key:
            return Response(
                {'error': 'Recipient has no RSA public key'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            encrypted = encrypt_message(data['plaintext'], recipient.public_key)
            message = Message.objects.create(
                sender=sender,
                recipient=recipient,
                ciphertext=encrypted['ciphertext'],
                encrypted_key=encrypted['encrypted_key'],
                nonce=encrypted['nonce'],
                auth_tag=encrypted['auth_tag'],
                signature=data['signature'],
            )
        except Exception as e:
            return Response(
                {'error': f'Error processing message: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Registro automático en el blockchain
        try:
            append_block(sender.id, recipient.id, data['plaintext'])
        except Exception as exc:
            logger.error('Blockchain append failed for message %s: %s', message.id, exc)

        return Response(
            {
                'id': str(message.id),
                'sender_id': str(message.sender.id),
                'recipient_id': str(message.recipient.id),
                'created_at': message.created_at.isoformat(),
            },
            status=status.HTTP_201_CREATED,
        )

    def _send_group_message(self, sender, group_id, data):
        if not GroupMember.objects.filter(group_id=group_id, user=sender).exists():
            return Response(
                {'error': 'You are not a member of this group'},
                status=status.HTTP_403_FORBIDDEN,
            )

        members = (
            GroupMember.objects
            .filter(group_id=group_id)
            .select_related('user')
        )

        plaintext_bytes = data['plaintext'].encode('utf-8')

        # Una sola clave AES y un solo ciphertext para todo el grupo
        aes_key = generate_aes_key()
        nonce = generate_nonce()
        ciphertext_bytes, auth_tag_bytes = encrypt_aes_gcm(plaintext_bytes, aes_key, nonce)

        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode('utf-8')
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')
        auth_tag_b64 = base64.b64encode(auth_tag_bytes).decode('utf-8')

        messages = []
        try:
            for member in members:
                if not member.user.public_key:
                    continue
                encrypted_key_bytes = encrypt_key_rsa_oaep(aes_key, member.user.public_key)
                encrypted_key_b64 = base64.b64encode(encrypted_key_bytes).decode('utf-8')

                msg = Message.objects.create(
                    sender=sender,
                    recipient=member.user,
                    group_id=group_id,
                    ciphertext=ciphertext_b64,
                    encrypted_key=encrypted_key_b64,
                    nonce=nonce_b64,
                    auth_tag=auth_tag_b64,
                    signature=data['signature'],
                )
                messages.append(msg)
        except Exception as e:
            return Response(
                {'error': f'Error processing group message: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        if not messages:
            return Response(
                {'error': 'No valid members with RSA keys found'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Registro automático en el blockchain — un bloque por evento grupal
        try:
            append_block(sender.id, None, data['plaintext'])
        except Exception as exc:
            logger.error('Blockchain append failed for group %s: %s', group_id, exc)

        return Response(
            {
                'group_id': str(group_id),
                'message_count': len(messages),
                'created_at': messages[0].created_at.isoformat(),
            },
            status=status.HTTP_201_CREATED,
        )


class CreateGroupView(APIView):
    def post(self, request):
        """
        POST /groups/
        Crea un grupo con los miembros indicados.
        El cliente es responsable de la distribución de claves (E2E).
        """
        sender, error = _authenticate_request(request)
        if error:
            return error

        serializer = CreateGroupSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        member_ids = data['member_ids']

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
            GroupMember(group=group, user=user) for user in users
        ])

        return Response(
            {
                'id': str(group.id),
                'name': group.name,
                'created_at': group.created_at.isoformat(),
                'members': [
                    {
                        'id': str(u.id),
                        'display_name': u.display_name,
                        'email': u.email,
                        'public_key': u.public_key,
                    }
                    for u in users
                ],
            },
            status=status.HTTP_201_CREATED,
        )


@csrf_exempt
@require_http_methods(["GET", "POST"])
@jwt_required
def verify_message(request, msg_id):
    """
    GET /messages/{msg_id}/verify
    El cliente descifra el mensaje localmente y envía el plaintext.
    El servidor verifica la firma ECDSA del remitente y persiste el resultado.

    Body: { "plaintext": "<texto descifrado>" }
    Response: { "message_id": str, "verified": bool, "reason"?: str }
    """
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'Invalid JSON body'}, status=400)

    plaintext = body.get('plaintext')
    if plaintext is None:
        return JsonResponse({'error': 'plaintext is required'}, status=400)

    try:
        message = Message.objects.select_related('sender').get(id=msg_id)
    except Message.DoesNotExist:
        return JsonResponse({'error': 'Message not found'}, status=404)

    if str(request.user.id) != str(message.recipient_id):
        return JsonResponse({'error': 'Access denied'}, status=403)

    verified = False
    reason = None

    if not message.signature:
        reason = 'no_signature'
    elif not message.sender.ecdsa_public_key:
        reason = 'no_ecdsa_key'
    else:
        plaintext_bytes = plaintext.encode('utf-8') if isinstance(plaintext, str) else plaintext
        verified = verify_signature(plaintext_bytes, message.signature, message.sender.ecdsa_public_key)
        if not verified:
            reason = 'invalid_signature'

    message.signature_verified = verified
    message.save(update_fields=['signature_verified'])

    response = {'message_id': str(msg_id), 'verified': verified}
    if reason:
        response['reason'] = reason
    return JsonResponse(response, status=200)


@csrf_exempt
@require_http_methods(["GET"])
def get_group(request, group_id):
    """
    GET /groups/{group_id}
    Retorna info del grupo con miembros y sus llaves públicas.
    El cliente usa las llaves públicas para cifrar la clave AES (E2E).
    """
    try:
        group = Group.objects.get(id=group_id)
    except Group.DoesNotExist:
        return JsonResponse({'error': 'Group not found'}, status=404)

    members = (
        GroupMember.objects
        .filter(group=group)
        .select_related('user')
    )

    return JsonResponse({
        'id': str(group.id),
        'name': group.name,
        'created_at': group.created_at.isoformat(),
        'members': [
            {
                'id': str(m.user.id),
                'display_name': m.user.display_name,
                'email': m.user.email,
                'public_key': m.user.public_key,
            }
            for m in members
        ],
    })


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
                'sender_name': msg.sender.display_name,
                'sender_email': msg.sender.email,
                'recipient_id': str(msg.recipient.id),
                'group_id': str(msg.group_id) if msg.group_id else None,
                'ciphertext': msg.ciphertext,
                'encrypted_key': msg.encrypted_key,
                'nonce': msg.nonce,
                'auth_tag': msg.auth_tag,
                'signature': msg.signature,
                'has_signature': bool(msg.signature),
                'signature_verified': msg.signature_verified,
                'created_at': msg.created_at.isoformat(),
            }
            for msg in messages
        ]

        return JsonResponse({'messages': messages_data}, status=200)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
