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
