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
from .serializers import SendMessageSerializer, CreateGroupSerializer


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
        Recibe el mensaje ya cifrado por el cliente (E2E encryption).
        Acepta recipient_id (directo) o group_id (grupal).

        Payload directo:
          { recipient_id, ciphertext, encrypted_key, nonce, auth_tag }

        Payload grupal:
          { group_id, ciphertext, nonce, auth_tag,
            encrypted_keys: [{user_id, encrypted_key}, ...] }
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

        try:
            message = Message.objects.create(
                sender=sender,
                recipient=recipient,
                ciphertext=data['ciphertext'],
                encrypted_key=data['encrypted_key'],
                nonce=data['nonce'],
                auth_tag=data['auth_tag'],
            )
        except Exception as e:
            return Response(
                {'error': f'Error storing message: {str(e)}'},
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

    def _send_group_message(self, sender, group_id, data):
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

        # Mapa user_id → encrypted_key enviado por el cliente
        encrypted_keys_map = {
            str(item['user_id']): item['encrypted_key']
            for item in data['encrypted_keys']
        }

        messages = []
        try:
            for member in members:
                user_id = str(member.user.id)
                encrypted_key = encrypted_keys_map.get(user_id, '')

                msg = Message.objects.create(
                    sender=sender,
                    recipient=member.user,
                    group_id=group_id,
                    ciphertext=data['ciphertext'],
                    encrypted_key=encrypted_key,
                    nonce=data['nonce'],
                    auth_tag=data['auth_tag'],
                )
                messages.append(msg)
        except Exception as e:
            return Response(
                {'error': f'Error storing group message: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {
                'group_id': str(group_id),
                'message_count': len(messages),
                'ciphertext': data['ciphertext'],
                'nonce': data['nonce'],
                'auth_tag': data['auth_tag'],
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
@require_http_methods(["GET"])
def get_group(request, group_id):
    """
    GET /groups/{group_id}
    Retorna info del grupo con miembros y sus llaves públicas.
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
                'created_at': msg.created_at.isoformat(),
            }
            for msg in messages
        ]

        return JsonResponse({'messages': messages_data}, status=200)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
