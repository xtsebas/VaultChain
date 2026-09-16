# Hallazgos de seguridad

Registro de vulnerabilidades identificadas y su remediación, en el contexto de la rama `fix/sebas-headers-pathtraversal`.

---

## 1. Missing Anti-clickjacking Header

**Severidad:** Baja

**Descripción:** El backend no enviaba explícitamente la cabecera `X-Frame-Options`. Aunque `django.middleware.clickjacking.XFrameOptionsMiddleware` ya estaba incluido en `MIDDLEWARE`, el valor de `X_FRAME_OPTIONS` no estaba definido en `settings.py`, dejando el comportamiento sujeto al default interno de Django en lugar de una configuración explícita y auditable.

**Riesgo:** Sin esta cabecera (o con un valor incorrecto), la aplicación podría ser embebida en un `<iframe>` de un sitio malicioso, habilitando ataques de clickjacking (por ejemplo, engañar al usuario para que haga clic en un botón de login o envío de mensaje sin saberlo).

**Archivo afectado:** [`backend/vaultchain/settings.py`](../backend/vaultchain/settings.py)

**Solución aplicada:**
```python
# Anti-clickjacking: fuerza X-Frame-Options: DENY en todas las respuestas
X_FRAME_OPTIONS = 'DENY'
```
Agregado explícitamente antes de la definición de `MIDDLEWARE`, reforzando el middleware ya existente.

**Verificación:**

Servidor local levantado con:
```bash
cd backend
source venv/bin/activate
DATABASE_URL= python manage.py runserver
```

Petición de prueba:
```bash
curl -i -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@vaultchain.test","password":"test123"}'
```

Respuesta observada (2026-09-16):
```
HTTP/1.1 401 Unauthorized
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
```

La cabecera `X-Frame-Options: DENY` está presente en todas las respuestas, incluyendo endpoints públicos como `/auth/login`. Confirmado.

**Estado:** Resuelto

---

## 2. Strict-Transport-Security Not Set

**Severidad:** Media

**Descripción:** El backend no tenía configurado HSTS (`Strict-Transport-Security`). Faltaban `SECURE_HSTS_SECONDS`, `SECURE_HSTS_INCLUDE_SUBDOMAINS` y `SECURE_HSTS_PRELOAD` en `settings.py`.

**Riesgo:** Sin HSTS, un navegador que ya visitó el sitio por HTTPS puede ser forzado (por un atacante en la red, ej. downgrade attack) a volver a conectarse por HTTP sin cifrar, exponiendo tokens JWT y credenciales a un ataque man-in-the-middle.

**Archivo afectado:** [`backend/vaultchain/settings.py`](../backend/vaultchain/settings.py)

**Solución aplicada:**
```python
# HSTS: fuerza HTTPS en el navegador durante SECURE_HSTS_SECONDS.
# SecurityMiddleware solo envia esta cabecera cuando request.is_secure() es True,
# por lo que no tiene efecto en desarrollo local sobre HTTP.
if not DEBUG:
    SECURE_HSTS_SECONDS = 31536000  # 1 año
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
```

La configuración se activa solo cuando `DEBUG=False` (producción), evitando enviar cabeceras HSTS accidentalmente en entornos de desarrollo que pudieran servir por HTTPS de forma esporádica.

**Nota importante:** `Strict-Transport-Security` solo se envía cuando la conexión es HTTPS real (`request.is_secure()`). En desarrollo local y en el `docker-compose.yml` actual (backend servido en HTTP plano, puerto 8000, sin terminación TLS) la cabecera **no puede aparecer** aunque el setting esté activo — este es el comportamiento esperado, no una falla.

**Verificación (2026-09-16):**

Se levantó el stack completo forzando `DEBUG=0`:
```bash
DEBUG=0 docker-compose up --build
```

Confirmación de que los settings quedaron activos dentro del contenedor:
```bash
docker-compose exec backend python manage.py shell -c \
  "from django.conf import settings; print(settings.SECURE_HSTS_SECONDS, settings.SECURE_HSTS_INCLUDE_SUBDOMAINS, settings.SECURE_HSTS_PRELOAD)"
```
Resultado:
```
31536000 True True
```

Petición de control a `/auth/login` (HTTP, sin HSTS visible como se esperaba, pero con `X-Frame-Options: DENY` intacto):
```
HTTP/1.1 401 Unauthorized
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
```

**Pendiente para producción real:** cuando el sistema se despliegue detrás de HTTPS (reverse proxy/load balancer con TLS), repetir la prueba con `curl -ik https://<dominio>/auth/login` para confirmar que `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` aparece en la respuesta.

**Estado:** Resuelto (configuración activa)

---

## 3. Path Traversal (alerta OWASP ZAP)

**Severidad:** Media

**Descripción:** Un escaneo automatizado con OWASP ZAP marcó una alerta de Path Traversal. Se investigó el código del backend en busca de cualquier endpoint que use un parámetro de usuario (nombre de archivo, ruta, identificador) para leer o servir un archivo del sistema (`open()`, `FileResponse`, `send_file`, `MEDIA_ROOT`, `request.FILES`, etc.).

**Hallazgo de la investigación:**
- No existe ningún endpoint que abra o sirva archivos usando input de usuario. El único caso de generación de archivo (el QR de TOTP en `auth_module/views.py`) se construye enteramente en memoria con `io.BytesIO()` y nunca toca el filesystem.
- Todos los parámetros dinámicos en las URLs (`auth_module/urls.py`, `crypto_module/urls.py`) usan el conversor `<uuid:...>` de Django, que valida el formato UUID en el router antes de que la request llegue a la vista.
- El único parámetro de query string usado en el proyecto (`?from=` en `blockchain/views.py`) se castea explícitamente con `int()`, rechazando cualquier valor no numérico.

**Corrección aplicada (defensa en profundidad):** aunque no se encontró un vector explotable hoy, se agregó un middleware global que rechaza cualquier request cuya ruta o query string contenga secuencias de path traversal (`../`, `..\`, `%2e%2e`, `..%2f`, `..%5c`, bytes nulos), antes de que la request llegue a cualquier vista. Esto protege contra endpoints futuros que pudieran manejar archivos sin la misma validación estricta que los actuales.

**Archivos afectados:**
- [`backend/middleware/path_traversal_middleware.py`](../backend/middleware/path_traversal_middleware.py) (nuevo)
- [`backend/vaultchain/settings.py`](../backend/vaultchain/settings.py)

**Solución aplicada:**
```python
# path_traversal_middleware.py
_TRAVERSAL_PATTERNS = ('../', '..\\', '%2e%2e', '..%2f', '..%5c', '\x00')

class PathTraversalProtectionMiddleware:
    def __call__(self, request):
        raw_target = urllib.parse.unquote(request.path + '?' + request.META.get('QUERY_STRING', ''))
        if any(pattern in raw_target.lower() for pattern in _TRAVERSAL_PATTERNS):
            return JsonResponse({'error': 'Invalid request path'}, status=400)
        return self.get_response(request)
```

Registrado en `MIDDLEWARE` inmediatamente después de `SecurityMiddleware`, para cortar la request lo antes posible en el ciclo.

**Verificación:**
```bash
docker-compose up --build
```
```bash
curl -i "http://localhost:8000/auth/users/../../../../etc/passwd/key"
curl -i "http://localhost:8000/messages/..%2f..%2f..%2fetc%2fpasswd"
curl -i "http://localhost:8000/blockchain/verify/from/?from=../../etc/passwd"
```
Resultado esperado en los tres casos: `400 Bad Request` con `{"error": "Invalid request path"}`, generado por el middleware antes de llegar al router/vista.

**Estado:** Resuelto
