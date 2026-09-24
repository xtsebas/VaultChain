import os
import urllib.parse

from django.http import JsonResponse

# Secuencias que indican un intento de path traversal en la URL o el query string.
_TRAVERSAL_PATTERNS = ('../', '..\\', '%2e%2e', '..%2f', '..%5c', '\x00')


class PathTraversalProtectionMiddleware:
    """
    Rechaza cualquier request cuya ruta o query string contenga secuencias
    de path traversal, antes de que llegue a cualquier vista.

    Defensa en profundidad: hoy ningún endpoint usa el path o el query string
    para abrir archivos (todos los parámetros dinámicos son UUID o enteros
    validados), pero este middleware protege contra futuros endpoints que
    lleguen a manejar archivos sin la misma validación estricta.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        raw_target = urllib.parse.unquote(request.path + '?' + request.META.get('QUERY_STRING', ''))
        lowered = raw_target.lower()

        if any(pattern in lowered for pattern in _TRAVERSAL_PATTERNS):
            return JsonResponse({'error': 'Invalid request path'}, status=400)

        return self.get_response(request)
