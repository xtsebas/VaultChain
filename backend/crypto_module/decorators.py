import jwt
from functools import wraps
from django.http import JsonResponse
from django.conf import settings
from auth_module.models import User


def jwt_required(f):
    """
    Decorador para proteger endpoints con autenticación JWT.
    Extrae el token del header Authorization y valida el JWT.
    """
    @wraps(f)
    def decorated_function(request, *args, **kwargs):
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            return JsonResponse(
                {'error': 'Missing or invalid Authorization header'},
                status=401
            )

        token = auth_header.split(' ')[1]

        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=['HS256']
            )

            if payload.get('type') != 'access':
                return JsonResponse(
                    {'error': 'Invalid token type'},
                    status=401
                )

            user_id = payload.get('user_id')
            if not user_id:
                return JsonResponse(
                    {'error': 'Invalid token payload'},
                    status=401
                )

            try:
                user = User.objects.get(id=user_id)
                request.user = user
            except User.DoesNotExist:
                return JsonResponse(
                    {'error': 'User not found'},
                    status=401
                )

        except jwt.ExpiredSignatureError:
            return JsonResponse(
                {'error': 'Token has expired'},
                status=401
            )
        except jwt.InvalidTokenError:
            return JsonResponse(
                {'error': 'Invalid token'},
                status=401
            )

        return f(request, *args, **kwargs)

    return decorated_function
