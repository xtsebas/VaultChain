from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from auth_module.models import User
from .models import Message
from .decorators import jwt_required
from .serializers import SendMessageSerializer, MessageResponseSerializer
from .encryption import encrypt_message


class SendMessageView(APIView):
    @csrf_exempt
    def post(self, request):
        """
        POST /messages
        Envía un mensaje cifrado con el flujo completo de cifrado híbrido.
        Protegido con JWT.
        """
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            return Response(
                {'error': 'Missing or invalid Authorization header'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        import jwt
        from django.conf import settings

        token = auth_header.split(' ')[1]

        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=['HS256']
            )

            if payload.get('type') != 'access':
                return Response(
                    {'error': 'Invalid token type'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user_id = payload.get('user_id')
            if not user_id:
                return Response(
                    {'error': 'Invalid token payload'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            try:
                sender = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response(
                    {'error': 'User not found'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

        except jwt.ExpiredSignatureError:
            return Response(
                {'error': 'Token has expired'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except jwt.InvalidTokenError:
            return Response(
                {'error': 'Invalid token'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        serializer = SendMessageSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        recipient_id = data['recipient_id']
        plaintext = data['plaintext']

        try:
            recipient = User.objects.get(id=recipient_id)
        except User.DoesNotExist:
            return Response(
                {'error': 'Recipient not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        try:
            encrypted_data = encrypt_message(plaintext, recipient.public_key)

            message = Message(
                sender=sender,
                recipient=recipient,
                ciphertext=encrypted_data['ciphertext'],
                encrypted_key=encrypted_data['encrypted_key'],
                nonce=encrypted_data['nonce'],
                auth_tag=encrypted_data['auth_tag'],
            )
            message.save()

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
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            return Response(
                {'error': f'Error encrypting message: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@csrf_exempt
@require_http_methods(["GET"])
@jwt_required
def get_user_messages(request, user_id):
    """
    GET /messages/{user_id}
    Obtiene todos los mensajes recibidos por un usuario.
    Protegido con JWT.
    """
    if str(request.user.id) != str(user_id):
        return JsonResponse(
            {'error': 'You can only access your own messages'},
            status=403
        )

    try:
        messages = Message.objects.filter(recipient_id=user_id).order_by('-created_at')

        messages_data = []
        for msg in messages:
            messages_data.append({
                'id': str(msg.id),
                'sender_id': str(msg.sender.id),
                'recipient_id': str(msg.recipient.id),
                'ciphertext': msg.ciphertext,
                'encrypted_key': msg.encrypted_key,
                'nonce': msg.nonce,
                'auth_tag': msg.auth_tag,
                'signature': msg.signature,
                'created_at': msg.created_at.isoformat(),
            })

        return JsonResponse(
            {'messages': messages_data},
            status=200
        )

    except Exception as e:
        return JsonResponse(
            {'error': str(e)},
            status=500
        )
