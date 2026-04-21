from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .models import User


@csrf_exempt
@require_http_methods(["GET"])
def get_user_public_key(request, user_id):
    """
    GET /users/{user_id}/key
    Retorna la llave pública del usuario en formato PEM.
    """
    try:
        user = User.objects.get(id=user_id)

        return HttpResponse(
            user.public_key,
            content_type='application/x-pem-file',
            status=200
        )
    except User.DoesNotExist:
        return JsonResponse(
            {"error": "User not found"},
            status=404
        )
    except Exception as e:
        return JsonResponse(
            {"error": str(e)},
            status=500
        )
