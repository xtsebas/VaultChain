# Parte 2 — Remediación: CORS, Reflected XSS y SQL Injection

Rama: `fix/davis-cors-xss-sqli`
Commits: `c15f1f0`, `488fbe7`, `e4b226d`

**Nota de alcance.** Antes de escribir el fix se auditó el repositorio completo (código + historial de git) buscando los tres patrones vulnerables. CORS ya usaba una allowlist estricta (`CORS_ALLOWED_ORIGINS`, no wildcard) y no existe ni existió nunca una consulta SQL cruda en VaultChain (el ORM se usa en el 100% de los accesos a datos). Por eso, en esas dos secciones el bloque **ANTES** es el patrón vulnerable de referencia de OWASP, no código que haya corrido en este proyecto — se deja así por transparencia académica. La sección de **Reflected XSS** sí documenta una vulnerabilidad real, encontrada y corregida, en `crypto_module/views.py`.

---

## 1. Cross-Domain Misconfiguration (CORS)

**CWE-942** — Permissive Cross-domain Policy with Untrusted Domains
**Severidad:** High → Low

> Patrón de referencia OWASP. `settings.py` de VaultChain ya usaba `CORS_ALLOWED_ORIGINS`, no un wildcard. El fix real endurece lo que faltaba: credenciales, métodos, headers y configurabilidad por entorno.

### ANTES (patrón vulnerable de referencia)

```python
# settings.py — cualquier origen puede leer respuestas autenticadas
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
```

### DESPUÉS (`backend/vaultchain/settings.py`)

```python
# Origins por env var, allowlist estricta, sin credenciales cross-origin
_default_dev_origins = (
    'http://localhost:5173,http://127.0.0.1:5173,'
    'http://localhost:3000,http://127.0.0.1:3000'
)
CORS_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        'CORS_ALLOWED_ORIGINS', _default_dev_origins
    ).split(',')
    if origin.strip()
]
CORS_ALLOW_CREDENTIALS = False
CORS_ALLOW_METHODS = ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS']
CORS_ALLOW_HEADERS = ['authorization', 'content-type']
```

### CVSS v3.1

| | Vector | Score | Severidad |
|---|---|---|---|
| Antes | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5** | High |
| Después | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | **3.7** | Low |

**Justificación:** con allowlist estricta + `CORS_ALLOW_CREDENTIALS=False`, el navegador bloquea la respuesta para cualquier origen fuera de la lista y nunca reenvía credenciales cross-site; la explotación pasa de trivial (`AC:L`) a requerir condiciones que ya no aplican en producción (`AC:H`, `C:H→C:L`), justificando la caída de 7.5 a 3.7.

Commit: `c15f1f0` — *fix: enforce strict CORS allowlist and disable credentials*

---

## 2. Reflected XSS / reflejo de datos crudos en respuestas JSON

**CWE-79** / **CWE-209** — Information Exposure Through an Error Message
**Severidad:** Medium → None

> Vulnerabilidad real, encontrada y corregida en `crypto_module/views.py` (3 endpoints).

### ANTES (`backend/crypto_module/views.py`)

```python
except Exception as e:
    return Response(
        {'error': f'Error processing message: {str(e)}'},
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
# str(e) reenvía al cliente contenido interno / derivado del input
```

### DESPUÉS (`backend/crypto_module/views.py`)

```python
except Exception:
    logger.exception(
        'Error processing direct message from %s to %s',
        sender.id, recipient_id,
    )
    return Response(
        {'error': 'Error processing message'},
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
# mensaje fijo al cliente; detalle real solo en logs server-side
```

El mismo patrón se aplicó a `_send_group_message` y a `get_user_messages`.

### CVSS v3.1

| | Vector | Score | Severidad |
|---|---|---|---|
| Antes | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | **6.1** | Medium |
| Después | Vector sin ruta explotable — nada reflejable queda en la respuesta | **0.0** | None |

**Justificación:** al fijar el mensaje de error y mover `str(e)` a `logger.exception`, ya no existe dato controlado ni derivado del input en el cuerpo de la respuesta (`C:L→C:N`, `I:L→I:N`); no queda superficie de reflejo que un cliente pueda inducir, así que el vector deja de ser explotable y el score cae a 0.0.

Commit: `488fbe7` — *fix: stop reflecting raw exception content in JSON error responses*

---

## 3. SQL Injection

**CWE-89** — Improper Neutralization of Special Elements used in an SQL Command
**Severidad:** Critical → None

> Patrón de referencia OWASP. No hay ni un solo `.raw()` / `cursor.execute()` en VaultChain, en ningún commit de su historial. El fix real es el guardrail de regresión que fija esa garantía como política.

### ANTES (patrón vulnerable de referencia)

```python
query = (
    "SELECT * FROM crypto_module_message "
    f"WHERE recipient_id = '{user_id}'"
)
cursor.execute(query)
```

### DESPUÉS (vigente en todo el repo, ej. `crypto_module/views.py`)

```python
messages = (
    Message.objects
    .filter(recipient_id=user_id)
    .order_by('-created_at')
)
```

Y como resguardo nuevo, `backend/tests/test_no_raw_sql.py` escanea `backend/**/*.py` (excluyendo migraciones/tests) y falla el build si aparece `.raw()`, `cursor.execute()`, `connection.cursor()` o `.extra()`.

### CVSS v3.1

| | Vector | Score | Severidad |
|---|---|---|---|
| Antes | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Critical |
| Después | Sin superficie de SQL crudo — no hay AV explotable | **0.0** | N/A |

**Justificación:** el ORM parametriza cada consulta por diseño, así que no existe un punto donde concatenar input de usuario dentro de SQL (`C:H/I:H/A:H → N/N/N`); el test de regresión convierte esa ausencia en una garantía verificable en CI, no solo en una observación puntual.

Commit: `e4b226d` — *test: add regression guard against raw/unparameterized SQL*

---

## Verificación

- Sintaxis de los 3 archivos modificados validada con `ast.parse`.
- `test_no_raw_sql.py` ejecutado standalone (pasa).
- Django no estaba instalado en este entorno, así que `manage.py test` completo **no** se corrió — pendiente antes de abrir el PR.

```
e4b226d test: add regression guard against raw/unparameterized SQL
488fbe7 fix: stop reflecting raw exception content in JSON error responses
c15f1f0 fix: enforce strict CORS allowlist and disable credentials
```
