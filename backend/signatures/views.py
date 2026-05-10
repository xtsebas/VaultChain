import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from crypto_module.decorators import jwt_required
from crypto_module.models import Message
from .ecdsa_utils import verify_signature


@csrf_exempt
@require_http_methods(["POST"])
@jwt_required
def verify_message_signature(request):
    """
    POST /signatures/verify/
    Verifica la firma ECDSA de un mensaje usando la llave publica del remitente.

    Body:
        message_id  (str UUID)  - ID del mensaje a verificar
        plaintext   (str)       - Texto descifrado del mensaje

    Response:
        { verified: bool, message_id: str }
        Si no hay firma almacenada o el remitente no tiene llave ECDSA, verified=false.
    """
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    message_id = body.get('message_id')
    plaintext = body.get('plaintext')

    if not message_id or plaintext is None:
        return JsonResponse(
            {'error': 'message_id and plaintext are required'},
            status=400,
        )

    try:
        message = Message.objects.select_related('sender').get(id=message_id)
    except Message.DoesNotExist:
        return JsonResponse({'error': 'Message not found'}, status=404)

    if str(request.user.id) != str(message.recipient_id):
        return JsonResponse({'error': 'Access denied'}, status=403)

    if not message.signature:
        return JsonResponse(
            {'verified': False, 'message_id': str(message_id), 'reason': 'no_signature'},
            status=200,
        )

    sender_ecdsa_public_key = message.sender.ecdsa_public_key
    if not sender_ecdsa_public_key:
        return JsonResponse(
            {'verified': False, 'message_id': str(message_id), 'reason': 'no_ecdsa_key'},
            status=200,
        )

    plaintext_bytes = plaintext.encode('utf-8') if isinstance(plaintext, str) else plaintext
    verified = verify_signature(plaintext_bytes, message.signature, sender_ecdsa_public_key)

    return JsonResponse({'verified': verified, 'message_id': str(message_id)}, status=200)
