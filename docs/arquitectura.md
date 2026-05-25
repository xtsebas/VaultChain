# Arquitectura de VaultChain

## Descripción general

VaultChain es un sistema de mensajería segura para el Ministerio de Finanzas Públicas de Guatemala. Implementa cuatro garantías criptográficas sobre cada mensaje: **confidencialidad** (AES-256-GCM + RSA-OAEP), **autenticidad** (ECDSA P-256), **integridad** (GCM auth tag + hash de bloque) y **trazabilidad no repudiable** (mini-blockchain SHA-256). Las llaves privadas nunca salen del cliente en texto plano.

---

## Capas del sistema

```
┌──────────────────────────────────────────────────────────────┐
│  Capa 4 — Sesión y despliegue                                │
│  JWT HS256 (access 1h / refresh 7d) · TOTP · Docker Compose │
├──────────────────────────────────────────────────────────────┤
│  Capa 3 — Firmas y auditoría                                 │
│  ECDSA P-256 · SHA-256 · Mini-blockchain                     │
├──────────────────────────────────────────────────────────────┤
│  Capa 2 — Cifrado híbrido                                    │
│  AES-256-GCM (contenido) · RSA-OAEP/SHA-256 (clave)         │
├──────────────────────────────────────────────────────────────┤
│  Capa 1 — Identidad                                          │
│  Argon2id (password) · RSA-2048 + ECDSA P-256 (llaves)      │
│  PBKDF2-HMAC-SHA256 + AES-256-GCM (cifrado de llave privada)│
└──────────────────────────────────────────────────────────────┘
```

---

## Stack tecnológico

| Componente | Tecnología | Versión |
|---|---|---|
| Backend | Django + Django REST Framework | 6.0.4 / 3.17.1 |
| Base de datos (dev) | SQLite | — |
| Base de datos (prod) | PostgreSQL | 15 |
| Frontend | React + Vite | — |
| Contenedores | Docker + Docker Compose | — |
| Hash de password | argon2-cffi (Argon2id) | 25.1.0 |
| Criptografía principal | cryptography (hazmat) | 46.0.5 |
| Cifrado simétrico/asimétrico | pycryptodome | 3.23.0 |
| JWT | PyJWT (HS256) | 2.12.1 |
| TOTP | pyotp | 2.9.0 |
| Códigos QR | qrcode + Pillow | 8.0 / 11.2.1 |
| Variables de entorno | python-dotenv | 1.0.0 |

---

## Servicios Docker

El archivo `docker-compose.yml` define tres servicios que se levantan en orden:

```
vaultchain_db        postgres:15      → puerto 5433 (host) : 5432 (contenedor)
vaultchain_backend   Django           → puerto 8000:8000
vaultchain_frontend  node:22          → puerto 3000 (host) : 5173 (contenedor)
```

**Orden de arranque:**
1. `db` arranca primero. El healthcheck (`pg_isready`) confirma que PostgreSQL acepta conexiones.
2. `backend` espera a que `db` esté healthy. Al iniciar ejecuta `migrate` automáticamente (incluyendo la inserción del bloque génesis).
3. `frontend` espera a que `backend` esté healthy (verifica `GET /auth/users/`), luego ejecuta `npm install && npm run dev --host`.

La base de datos se selecciona automáticamente en `settings.py`: si la variable `DATABASE_URL` está definida se usa PostgreSQL; de lo contrario SQLite (desarrollo local sin Docker).

---

## Estructura de módulos Django

```
backend/
├── vaultchain/          # Configuración del proyecto (settings, urls raíz, WSGI)
├── auth_module/         # Módulo 1: Identidad, registro, login, MFA, JWT
├── crypto_module/       # Módulo 2: Cifrado híbrido, mensajes, grupos
├── signatures/          # Módulo 3: Firmas ECDSA, verificación
├── blockchain/          # Módulo 3: Mini-blockchain, bloques, cadena
├── middleware/          # JWTAuthMiddleware global
└── api/                 # App base (modelos compartidos)
```

---

## Esquema de base de datos

### Tabla `users` (auth_module)

| Campo | Tipo | Descripción |
|---|---|---|
| id | UUID (PK) | Generado con `uuid4` |
| email | VARCHAR(255) | Único, indexado |
| display_name | VARCHAR(100) | Nombre visible |
| password_hash | VARCHAR(255) | Hash Argon2id |
| public_key | TEXT | Llave pública RSA-2048 en PEM |
| encrypted_private_key | TEXT | Llave privada RSA cifrada: `base64(salt):base64(nonce):base64(ciphertext+tag)` |
| ecdsa_public_key | TEXT | Llave pública ECDSA P-256 en PEM |
| encrypted_ecdsa_private_key | TEXT | Llave privada ECDSA cifrada (mismo formato) |
| totp_secret | VARCHAR(32) | Secreto TOTP (nullable) |
| mfa_enabled | BOOLEAN | `false` hasta confirmar con `/auth/mfa/confirm` |
| created_at | TIMESTAMP | Auto |

### Tabla `messages` (crypto_module)

| Campo | Tipo | Descripción |
|---|---|---|
| id | UUID (PK) | — |
| sender_id | UUID (FK → users) | — |
| recipient_id | UUID (FK → users, nullable) | Null si es grupal |
| group_id | UUID (nullable) | Referencia al grupo |
| ciphertext | TEXT | AES-256-GCM, Base64 |
| encrypted_key | TEXT | Clave AES cifrada con RSA-OAEP, Base64 |
| nonce | VARCHAR(24) | 12 bytes aleatorios, Base64 |
| auth_tag | VARCHAR(24) | 16 bytes GCM tag, Base64 |
| signature | TEXT | Firma ECDSA DER, Base64 (nullable) |
| signature_verified | BOOLEAN | `null` = no verificado, `true/false` = resultado |
| created_at | TIMESTAMP | Auto |

Índices en `sender_id` y `recipient_id`.

### Tabla `groups` / `group_members` (crypto_module)

| Tabla | Campos relevantes |
|---|---|
| groups | id (UUID PK), name, created_at |
| group_members | group_id (FK), user_id (FK), encrypted_key (nullable) — unique(group, user) |

### Tabla `blockchain` (blockchain)

| Campo | Tipo | Descripción |
|---|---|---|
| index | INTEGER (unique) | Número secuencial |
| timestamp | DATETIME | Momento de creación |
| sender_id | UUID (nullable) | Remitente del mensaje |
| recipient_id | UUID (nullable) | Destinatario (null si grupal) |
| message_hash | VARCHAR(64) | SHA-256 del plaintext original |
| previous_hash | VARCHAR(64) | Hash del bloque anterior |
| nonce | INTEGER | 0 (no hay proof-of-work) |
| hash | VARCHAR(64) | SHA-256 del bloque completo (unique) |

---

## Subsistemas criptográficos

### 1. Almacenamiento de contraseñas — Argon2id

```
password → Argon2id → password_hash  (almacenado en BD)
```

Implementado con `argon2-cffi`. Los parámetros por defecto de la librería se usan directamente (`PasswordHasher()`), que selecciona configuraciones resistentes a ataques de fuerza bruta con memoria y paralelismo.

### 2. Par de llaves RSA-2048 (cifrado de mensajes)

Al registrarse se genera un par RSA-2048 con exponente público 65537. La llave pública se almacena en PEM. La privada se cifra así:

```
1. salt   = os.urandom(32)
2. key    = PBKDF2-HMAC-SHA256(password, salt, iterations=600_000) → 32 bytes
3. nonce  = os.urandom(12)
4. {ciphertext, tag} = AES-256-GCM(encrypt, private_key_DER, key, nonce)
5. stored = base64(salt) + ":" + base64(nonce) + ":" + base64(ciphertext||tag)
```

El servidor nunca ve la llave privada en texto plano. El cliente la descifra localmente al recibir `encrypted_private_key` en el login, usando la contraseña que solo el usuario conoce.

### 3. Par de llaves ECDSA P-256 (firmas digitales)

Al registrarse también se genera un par ECDSA sobre la curva SECP256R1. La llave privada se cifra con el mismo esquema PBKDF2 + AES-256-GCM pero con una salt independiente. El cliente usa esta llave para firmar cada mensaje antes de enviarlo.

El verificador acepta dos formatos de firma para compatibilidad cliente-servidor:
- **DER** (ASN.1): producido por la librería `cryptography` de Python.
- **P1363 / raw r‖s** (64 bytes): producido por la Web Crypto API del navegador.

### 4. Cifrado híbrido AES-256-GCM + RSA-OAEP

**Cifrado (servidor, al recibir POST /messages/):**

```
aes_key = os.urandom(32)                          # clave efímera
nonce   = os.urandom(12)                          # 96 bits, único por mensaje
{ciphertext, auth_tag} = AES-256-GCM(plaintext, aes_key, nonce)
encrypted_key = RSA-OAEP(SHA-256)(aes_key, public_key_dest)
```

Todos los campos se almacenan en Base64.

**Descifrado (cliente):**

```
aes_key   = RSA-OAEP(SHA-256)(encrypted_key, private_key_dest)
plaintext = AES-256-GCM(decrypt, ciphertext, aes_key, nonce, auth_tag)
```

Si el `auth_tag` no coincide, `AES.MODE_GCM.decrypt_and_verify()` lanza `ValueError`, detectando alteración del mensaje.

**Mensajes grupales:** se genera una única clave AES y un único ciphertext. La clave AES se cifra por separado con la llave pública de cada miembro del grupo, generando una fila en `messages` por miembro.

### 5. Mini-blockchain

El hash de cada bloque cubre todos sus campos:

```python
SHA-256(json.dumps({
    "index":         ...,
    "timestamp":     ...,  # ISO 8601
    "sender_id":     ...,
    "recipient_id":  ...,
    "message_hash":  SHA-256(plaintext),
    "previous_hash": ...,
    "nonce":         0,
}, sort_keys=True))
```

El **bloque génesis** (índice 0) se inserta mediante una migración de Django (`0002_genesis_block.py`) con timestamp `2025-01-01T00:00:00Z` y `previous_hash = "0" * 64`. La migración es idempotente.

`append_block()` usa `select_for_update()` dentro de una transacción atómica para serializar escrituras concurrentes y garantizar que el índice sea siempre consecutivo.

### 6. JWT (HS256)

Dos tipos de token emitidos al login:

| Token | Payload | Vigencia |
|---|---|---|
| access | `{user_id, email, exp, iat, type: "access"}` | 1 hora |
| refresh | `{user_id, exp, iat, type: "refresh"}` | 7 días |

Algoritmo: HMAC-SHA256 con `SECRET_KEY` del settings. El `type` se valida explícitamente para evitar que un refresh token se use como access token.

### 7. MFA — TOTP

Flujo de activación en dos pasos:
1. `POST /auth/mfa/enable` → genera secreto con `pyotp.random_base32()`, lo guarda en `totp_secret`, retorna el QR en Base64 y la URI `otpauth://`. `mfa_enabled` sigue siendo `false`.
2. `POST /auth/mfa/confirm` → el usuario ingresa el código del app; si es válido se activa `mfa_enabled = true` y se emiten tokens JWT.

Flujo de login con MFA activo:
1. `POST /auth/login` → retorna `{mfa_required: true, email}` sin tokens.
2. `POST /auth/mfa/verify` → recibe `{email, totp_code}`; si es válido emite tokens JWT completos.

`pyotp.TOTP.verify()` usa `valid_window=1`, aceptando el código del intervalo anterior para tolerar desfases de reloj de hasta 30 segundos.

---

## Flujo completo de un mensaje

```
CLIENTE REMITENTE                          SERVIDOR                      CLIENTE DESTINATARIO
─────────────────                          ────────                      ────────────────────
1. GET /auth/users/{dest_id}/key
                          ←── public_key_RSA_PEM ──
2. Descifrar encrypted_ecdsa_private_key
   con PBKDF2(password) + AES-GCM
3. sign = ECDSA_P256_SHA256(plaintext, ecdsa_priv)

4. POST /messages/
   { recipient_id, plaintext, signature }
                          ─────────────────────────→
                          5. Validar JWT
                          6. aes_key = os.urandom(32)
                             nonce   = os.urandom(12)
                             ciphertext = AES-256-GCM(plaintext, aes_key, nonce)
                             enc_key    = RSA-OAEP(aes_key, public_key_dest)
                          7. INSERT INTO messages (...)
                          8. append_block(sender_id, recipient_id, plaintext)
                          ←── 201 Created ──

9. GET /messages/{dest_id}            (autenticado como destinatario)
                          ─────────────────────────→
                          ←── { messages: [...] } ──
10. Descifrar encrypted_private_key
    con PBKDF2(password) + AES-GCM
11. aes_key   = RSA-OAEP(enc_key, rsa_priv)
    plaintext = AES-256-GCM(ciphertext, aes_key, nonce, auth_tag)

12. POST /signatures/verify/
    { message_id, plaintext }
                          ─────────────────────────→
                          13. verify_signature(plaintext, signature,
                                               sender.ecdsa_public_key)
                          14. message.signature_verified = True/False
                          ←── { verified: true/false } ──
```

---

## Autenticación HTTP

Un middleware global (`JWTAuthMiddleware`) valida el JWT en cada request antes de llegar a la vista. Las rutas públicas (sin token) son:

```
/auth/register
/auth/login
/auth/mfa/verify
/auth/token/refresh
/auth/users/*       (listar usuarios y obtener llaves públicas)
/blockchain/*       (lectura pública de la cadena)
/admin/*
```

El resto requiere `Authorization: Bearer <access_token>`.

---

## Decisiones de diseño

| Decisión | Alternativa descartada | Motivo |
|---|---|---|
| Argon2id para passwords | bcrypt | Resistencia superior a ataques GPU/ASIC; recomendado en Password Hashing Competition |
| PBKDF2 (600 000 iter.) para derivar clave de cifrado de llave privada | scrypt | Compatibilidad sin dependencias extra; 600 K iteraciones cumplen la recomendación NIST SP 800-132 |
| RSA-2048 para cifrado de mensajes | ECC (ECIES) | Soporte nativo en pycryptodome con RSA-OAEP; suficiente para el prototipo |
| ECDSA P-256 para firmas | RSA-PSS | Firmas más cortas; compatible con Web Crypto API del navegador |
| `verify_signature` acepta DER y P1363 | Solo DER | Web Crypto API produce P1363; la compatibilidad evita errores de verificación desde el frontend |
| AES-256-GCM | AES-256-CBC | GCM provee autenticación integrada (AEAD); detecta alteraciones sin HMAC adicional |
| Hash SHA-256 con `sort_keys=True` en blockchain | Concatenación de strings | JSON con claves ordenadas garantiza determinismo del hash independientemente del intérprete |
| `select_for_update()` en `append_block` | Sin bloqueo | Evita que dos peticiones concurrentes generen bloques con el mismo índice o rompan el encadenamiento |
| Genesis block como migración de Django | Inserción manual | La migración es idempotente y se aplica automáticamente en cada entorno nuevo |
| Llaves privadas almacenadas cifradas en BD | Almacenamiento solo en cliente | Permite recuperar la sesión desde cualquier dispositivo sin sacrificar confidencialidad (server-side encrypted) |
| Nonce = 0 en blockchain (sin PoW) | Proof-of-work con dificultad | El sistema es de auditoría interna, no requiere consenso distribuido; el encadenamiento SHA-256 garantiza integridad |
