import jwt
from django.conf import settings
from django.http import JsonResponse

from auth_module.models import User

# Rutas que no requieren JWT
_PUBLIC_PATHS = frozenset([
    '/auth/register',
    '/auth/login',
    '/auth/mfa/verify',    
    '/auth/token/refresh', 
])

# Prefijos públicos (rutas que empiezan con estos no requieren JWT)
_PUBLIC_PREFIXES = (
    '/admin/',
    '/auth/users/',  
    '/blockchain/',  
)


class JWTAuthMiddleware:
    """
    Middleware que valida el JWT en cada request protegido.
    Rutas públicas definidas en _PUBLIC_PATHS y _PUBLIC_PREFIXES no requieren token.
    Retorna 401 si el token está ausente, expirado o es inválido.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if self._is_public(request.path):
            return self.get_response(request)

        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return JsonResponse(
                {'error': 'Missing or invalid Authorization header'},
                status=401,
            )

        token = auth_header.split(' ', 1)[1]

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid token'}, status=401)

        if payload.get('type') != 'access':
            return JsonResponse({'error': 'Invalid token type'}, status=401)

        user_id = payload.get('user_id')
        if not user_id:
            return JsonResponse({'error': 'Invalid token payload'}, status=401)

        try:
            request.user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=401)

        return self.get_response(request)

    @staticmethod
    def _is_public(path):
        if path in _PUBLIC_PATHS:
            return True
        return any(path.startswith(prefix) for prefix in _PUBLIC_PREFIXES)