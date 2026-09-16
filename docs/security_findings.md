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
