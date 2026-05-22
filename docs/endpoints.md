# API Endpoints — VaultChain

Base URL (local): `http://localhost:8000`

Todos los endpoints que requieren autenticación esperan el header:
```
Authorization: Bearer <access_token>
```

---

## Índice

- [Autenticación](#autenticación)
  - [POST /auth/register](#post-authregister)
  - [POST /auth/login](#post-authlogin)
  - [POST /auth/token/refresh](#post-authtokenrefresh)
  - [POST /auth/mfa/enable](#post-authmfaenable)
  - [POST /auth/mfa/confirm](#post-authmfaconfirm)
  - [POST /auth/mfa/verify](#post-authmfaverify)
  - [POST /auth/mfa/disable](#post-authmfadisable)
  - [GET /auth/users/](#get-authusers)
  - [GET /auth/users/{user_id}/key](#get-authusersuseridkey)
- [Mensajes](#mensajes)
  - [POST /messages/](#post-messages)
  - [GET /messages/{user_id}](#get-messagesuserid)
  - [POST /messages/{msg_id}/verify](#post-messagesmsgidverify)
- [Grupos](#grupos)
  - [POST /groups/](#post-groups)
  - [GET /groups/{group_id}](#get-groupsgroupid)
- [Firmas Digitales](#firmas-digitales)
  - [POST /signatures/verify/](#post-signaturesverify)
- [Blockchain](#blockchain)
  - [GET /blockchain/](#get-blockchain)
  - [GET /blockchain/verify/](#get-blockchainverify)
  - [GET /blockchain/verify/from/](#get-blockchainverifyfrom)

---

## Autenticación

### POST /auth/register

Registra un nuevo usuario. Genera automáticamente un par de llaves RSA-2048 (cifrado) y un par ECDSA P-256 (firmas). La llave privada se cifra con una clave derivada de la contraseña mediante PBKDF2 + AES-256-GCM antes de almacenarse.

**No requiere autenticación.**

**Body:**
```json
{
  "email": "ana.garcia@minfin.gob.gt",
  "display_name": "Ana García",
  "password": "Segura#2026!"
}
```

**Respuesta exitosa — 201 Created:**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "email": "ana.garcia@minfin.gob.gt",
  "display_name": "Ana García",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----\n",
  "created_at": "2026-05-21T14:30:00.123456+00:00"
}
```

**Errores:**

| Código | Descripción |
|--------|-------------|
| 400 | Campos inválidos o faltantes |
| 409 | El email ya está registrado |

---

### POST /auth/login

Verifica la contraseña con Argon2id y emite tokens JWT. Si el usuario tiene MFA activo, retorna `mfa_required: true` en lugar de los tokens; el cliente debe continuar con `/auth/mfa/verify`.

**No requiere autenticación.**

**Body:**
```json
{
  "email": "ana.garcia@minfin.gob.gt",
  "password": "Segura#2026!"
}
```

**Respuesta exitosa (sin MFA) — 200 OK:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "encrypted_private_key": "base64salt:base64nonce:base64ciphertext",
  "encrypted_ecdsa_private_key": "base64salt:base64nonce:base64ciphertext",
  "user": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "email": "ana.garcia@minfin.gob.gt",
    "display_name": "Ana García",
    "mfa_enabled": false
  }
}
```

**Respuesta cuando MFA está activo — 200 OK:**
```json
{
  "mfa_required": true,
  "email": "ana.garcia@minfin.gob.gt"
}
```

**Errores:**

| Código | Descripción |
|--------|-------------|
| 400 | Campos faltantes |
| 401 | Credenciales inválidas |

---

### POST /auth/token/refresh

Emite un nuevo `access_token` a partir de un `refresh_token` válido.

**No requiere autenticación.**

**Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Respuesta exitosa — 200 OK:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Errores:**

| Código | Descripción |
|--------|-------------|
| 400 | `refresh_token` ausente |
| 401 | Token expirado o inválido |

---

### POST /auth/mfa/enable

Primer paso para activar MFA. Genera un secreto TOTP, lo guarda en la cuenta y retorna el código QR para escanear con Google Authenticator. El MFA **no queda activo** hasta confirmar con `/auth/mfa/confirm`.

**Requiere autenticación.**

**Body:** vacío (`{}`)

**Respuesta exitosa — 200 OK:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "provisioning_uri": "otpauth://totp/VaultChain:ana.garcia@minfin.gob.gt?secret=JBSWY3DPEHPK3PXP&issuer=VaultChain",
  "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
}
```

**Errores:**

| Código | Descripción |
|--------|-------------|
| 401 | JWT ausente, inválido o expirado |

---

### POST /auth/mfa/confirm

Segundo paso del setup de MFA. Verifica que el usuario escaneó correctamente el QR ingresando el código TOTP actual. Si es válido, activa `mfa_enabled = true` y emite tokens JWT.

**Requiere autenticación.**

**Body:**
```json
{
  "totp_code": "482931"
}
```

**Respuesta exitosa — 200 OK:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "encrypted_private_key": "base64salt:base64nonce:base64ciphertext",
  "encrypted_ecdsa_private_key": "base64salt:base64nonce:base64ciphertext",
  "user": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "email": "ana.garcia@minfin.gob.gt",
    "display_name": "Ana García",
    "mfa_enabled": true
  }
}
```

**Errores:**

| Código | Descripción |
|--------|-------------|
| 400 | `totp_code` ausente o MFA ya activo |
| 401 | Código TOTP inválido o JWT inválido |

---

### POST /auth/mfa/verify

Verifica el código TOTP durante el login. Se usa después de que `/auth/login` retorna `mfa_required: true`. Si el código es válido, emite los tokens JWT completos.

**No requiere autenticación.**

**Body:**
```json
{
  "email": "ana.garcia@minfin.gob.gt",
  "totp_code": "482931"
}
```

**Respuesta exitosa — 200 OK:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "encrypted_private_key": "base64salt:base64nonce:base64ciphertext",
  "encrypted_ecdsa_private_key": "base64salt:base64nonce:base64ciphertext",
  "user": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "email": "ana.garcia@minfin.gob.gt",
    "display_name": "Ana García",
    "mfa_enabled": true
  }
}
```

**Errores:**

| Código | Descripción |
|--------|-------------|
| 400 | Campos faltantes o MFA no activo |
| 401 | Código TOTP inválido o usuario no encontrado |

---

### POST /auth/mfa/disable

Desactiva MFA. Requiere confirmar la contraseña actual.

**Requiere autenticación.**

**Body:**
```json
{
  "password": "Segura#2026!"
}
```

**Respuesta exitosa — 200 OK:**
```json
{
  "message": "MFA disabled successfully"
}
```

**Errores:**

| Código | Descripción |
|--------|-------------|
| 400 | `password` ausente |
| 401 | Contraseña incorrecta o JWT inválido |

---

### GET /auth/users/

Lista todos los usuarios registrados. Usado por el frontend para seleccionar destinatarios al enviar mensajes.

**No requiere autenticación.**

**Respuesta exitosa — 200 OK:**
```json
{
  "users": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "email": "ana.garcia@minfin.gob.gt",
      "display_name": "Ana García"
    },
    {
      "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "email": "pedro.lopez@minfin.gob.gt",
      "display_name": "Pedro López"
    }
  ]
}
```

---

### GET /auth/users/{user_id}/key

Retorna la llave pública RSA-2048 del usuario en formato PEM. El remitente la necesita para cifrar la clave AES efímera antes de enviar un mensaje.

**No requiere autenticación.**

**Respuesta exitosa — 200 OK** (`Content-Type: application/x-pem-file`):
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a7TjX3pq0eRkKLmN9Xw
v8T2oJzVYkBqP1Fs6WmH4cDxR3nZeG7uMpQlSt0OyUwAi5HNdKbXcFjE8vR2Lg==
-----END PUBLIC KEY-----
```

**Errores:**

| Código | Descripción |
|--------|-------------|
| 404 | Usuario no encontrado |

---

## Mensajes

### POST /messages/

Envía un mensaje cifrado y firmado digitalmente. El cliente debe:
1. Firmar `SHA-256(plaintext)` con su llave privada ECDSA
2. Enviar el `plaintext` en texto plano junto con la firma
3. El servidor cifra con AES-256-GCM y RSA-OAEP, y registra automáticamente un bloque en el blockchain

**Requiere autenticación.**

**Body — mensaje directo:**
```json
{
  "recipient_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
  "plaintext": "El presupuesto aprobado para Q1 es Q45,000,000.",
  "signature": "MEUCIQD3x9Kp...base64_firma_ecdsa..."
}
```

**Body — mensaje grupal:**
```json
{
  "group_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "plaintext": "Reunión de auditoría el viernes a las 10:00.",
  "signature": "MEUCIQD3x9Kp...base64_firma_ecdsa..."
}
```

**Respuesta exitosa (directo) — 201 Created:**
```json
{
  "id": "d4e5f6a7-b8c9-0123-defa-234567890123",
  "sender_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "recipient_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
  "created_at": "2026-05-21T14:45:00.000000+00:00"
}
```

**Respuesta exitosa (grupal) — 201 Created:**
```json
{
  "group_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "message_count": 3,
  "created_at": "2026-05-21T14:45:00.000000+00:00"
}
```

**Errores:**

| Código | Descripción |
|--------|-------------|
| 400 | Campos inválidos o destinatario sin llave pública |
| 401 | JWT ausente o inválido |
| 403 | No eres miembro del grupo |
| 404 | Destinatario o grupo no encontrado |

---

### GET /messages/{user_id}

Obtiene todos los mensajes recibidos por un usuario (ordenados por fecha descendente). Solo el propio usuario puede consultar su buzón.

**Requiere autenticación.**

**Respuesta exitosa — 200 OK:**
```json
{
  "messages": [
    {
      "id": "d4e5f6a7-b8c9-0123-defa-234567890123",
      "sender_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "sender_name": "Ana García",
      "sender_email": "ana.garcia@minfin.gob.gt",
      "recipient_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "group_id": null,
      "ciphertext": "base64_ciphertext...",
      "encrypted_key": "base64_encrypted_aes_key...",
      "nonce": "base64_nonce==",
      "auth_tag": "base64_auth_tag==",
      "signature": "MEUCIQD3x9Kp...base64_firma_ecdsa...",
      "has_signature": true,
      "signature_verified": null,
      "created_at": "2026-05-21T14:45:00.000000+00:00"
    }
  ]
}
```

> `signature_verified` es `null` si aún no se ha llamado al endpoint de verificación, `true` si fue verificado exitosamente, `false` si la firma no coincide.

**Errores:**

| Código | Descripción |
|--------|-------------|
| 401 | JWT ausente o inválido |
| 403 | Intentando acceder a mensajes de otro usuario |

---

### POST /messages/{msg_id}/verify

Verifica la firma ECDSA de un mensaje. El cliente descifra localmente el mensaje, y envía el `plaintext` al servidor. El servidor recalcula el hash y verifica la firma con la llave ECDSA pública del remitente. Solo el destinatario puede verificar un mensaje.

**Requiere autenticación.**

**Body:**
```json
{
  "plaintext": "El presupuesto aprobado para Q1 es Q45,000,000."
}
```

**Respuesta exitosa — 200 OK:**
```json
{
  "message_id": "d4e5f6a7-b8c9-0123-defa-234567890123",
  "verified": true
}
```

**Respuesta cuando la firma no coincide — 200 OK:**
```json
{
  "message_id": "d4e5f6a7-b8c9-0123-defa-234567890123",
  "verified": false,
  "reason": "invalid_signature"
}
```

**Posibles valores de `reason`:**

| Valor | Descripción |
|-------|-------------|
| `invalid_signature` | La firma no coincide con el contenido |
| `no_signature` | El mensaje no tiene firma almacenada |
| `no_ecdsa_key` | El remitente no tiene llave ECDSA pública |

**Errores:**

| Código | Descripción |
|--------|-------------|
| 400 | `plaintext` ausente o JSON inválido |
| 401 | JWT ausente o inválido |
| 403 | No eres el destinatario del mensaje |
| 404 | Mensaje no encontrado |

---

## Grupos

### POST /groups/

Crea un grupo con los miembros indicados. El servidor devuelve las llaves públicas de todos los miembros para que el cliente cifre la clave AES de forma independiente para cada uno (cifrado E2E).

**Requiere autenticación.**

**Body:**
```json
{
  "name": "Comité de Auditoría Q2",
  "member_ids": [
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "b2c3d4e5-f6a7-8901-bcde-f12345678901",
    "c3d4e5f6-a7b8-9012-cdef-123456789012"
  ]
}
```

**Respuesta exitosa — 201 Created:**
```json
{
  "id": "e5f6a7b8-c9d0-1234-efab-345678901234",
  "name": "Comité de Auditoría Q2",
  "created_at": "2026-05-21T15:00:00.000000+00:00",
  "members": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "display_name": "Ana García",
      "email": "ana.garcia@minfin.gob.gt",
      "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
    },
    {
      "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "display_name": "Pedro López",
      "email": "pedro.lopez@minfin.gob.gt",
      "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
    }
  ]
}
```

**Errores:**

| Código | Descripción |
|--------|-------------|
| 400 | Campos inválidos |
| 401 | JWT ausente o inválido |
| 404 | Uno o más `member_ids` no existen |

---

### GET /groups/{group_id}

Retorna la información del grupo incluyendo los miembros y sus llaves públicas RSA. Usado por el cliente para obtener las llaves antes de enviar un mensaje grupal.

**No requiere autenticación.**

**Respuesta exitosa — 200 OK:**
```json
{
  "id": "e5f6a7b8-c9d0-1234-efab-345678901234",
  "name": "Comité de Auditoría Q2",
  "created_at": "2026-05-21T15:00:00.000000+00:00",
  "members": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "display_name": "Ana García",
      "email": "ana.garcia@minfin.gob.gt",
      "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
    }
  ]
}
```

**Errores:**

| Código | Descripción |
|--------|-------------|
| 404 | Grupo no encontrado |

---

## Firmas Digitales

### POST /signatures/verify/

Verifica la firma ECDSA de un mensaje. Alternativa centralizada al endpoint `/messages/{msg_id}/verify`. Solo el destinatario del mensaje puede verificarlo.

**Requiere autenticación.**

**Body:**
```json
{
  "message_id": "d4e5f6a7-b8c9-0123-defa-234567890123",
  "plaintext": "El presupuesto aprobado para Q1 es Q45,000,000."
}
```

**Respuesta exitosa — 200 OK:**
```json
{
  "verified": true,
  "message_id": "d4e5f6a7-b8c9-0123-defa-234567890123"
}
```

**Respuesta cuando la firma no es válida — 200 OK:**
```json
{
  "verified": false,
  "message_id": "d4e5f6a7-b8c9-0123-defa-234567890123",
  "reason": "no_signature"
}
```

**Errores:**

| Código | Descripción |
|--------|-------------|
| 400 | Campos faltantes o JSON inválido |
| 401 | JWT ausente o inválido |
| 403 | No eres el destinatario del mensaje |
| 404 | Mensaje no encontrado |

---

## Blockchain

### GET /blockchain/

Retorna la cadena completa de bloques ordenados por índice. Cada bloque registra un evento de mensaje (sender, recipient, hash del plaintext).

**No requiere autenticación.**

**Respuesta exitosa — 200 OK:**
```json
{
  "length": 3,
  "chain": [
    {
      "index": 0,
      "timestamp": "2026-05-21T14:00:00.000000+00:00",
      "sender_id": null,
      "recipient_id": null,
      "message_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "nonce": 0,
      "hash": "a3f2c1b8d9e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0"
    },
    {
      "index": 1,
      "timestamp": "2026-05-21T14:45:00.000000+00:00",
      "sender_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "recipient_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "message_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "previous_hash": "a3f2c1b8d9e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
      "nonce": 12483,
      "hash": "0002f8a1c4e7b9d3f6a2c8e4b0d7f3a9c5e1b7d4f0a6c2e8b4d0f7a3c9e5b1d7"
    }
  ]
}
```

> El bloque génesis (índice 0) tiene `previous_hash` de 64 ceros.

---

### GET /blockchain/verify/

Verifica la integridad de la cadena completa. Para cada bloque comprueba:
1. Que el hash almacenado coincida con `SHA-256(index + timestamp + datos + previous_hash + nonce)`
2. Que `previous_hash` apunte correctamente al hash del bloque anterior

**No requiere autenticación.**

**Respuesta cuando la cadena es íntegra — 200 OK:**
```json
{
  "valid": true,
  "length": 5,
  "detail": "Cadena íntegra. 5 bloque(s) verificado(s)."
}
```

**Respuesta cuando hay una inconsistencia — 200 OK:**
```json
{
  "valid": false,
  "failed_at_index": 3,
  "reason": "hash_mismatch",
  "detail": "El hash almacenado del bloque #3 no coincide con su compute_hash()."
}
```

**Posibles valores de `reason`:**

| Valor | Descripción |
|-------|-------------|
| `hash_mismatch` | El hash del bloque fue alterado |
| `broken_link` | `previous_hash` no apunta al bloque anterior |

---

### GET /blockchain/verify/from/

Verifica la integridad de la cadena desde el bloque génesis hasta el bloque indicado (inclusive). Útil para auditar un rango específico.

**No requiere autenticación.**

**Query param:** `?from=<index>` (entero, requerido)

**Ejemplo:** `GET /blockchain/verify/from/?from=10`

**Respuesta cuando el rango es íntegro — 200 OK:**
```json
{
  "valid": true,
  "from_index": 10,
  "length": 11,
  "detail": "Cadena íntegra desde genesis hasta bloque #10. 11 bloque(s) verificado(s)."
}
```

**Respuesta cuando hay una inconsistencia — 200 OK:**
```json
{
  "valid": false,
  "from_index": 10,
  "failed_at_index": 7,
  "reason": "broken_link",
  "detail": "El bloque #7 apunta a previous_hash=0002f8a1c4e7b9… pero el hash del bloque #6 es 000a3f2c1b8d9e…"
}
```

**Errores:**

| Código | Descripción |
|--------|-------------|
| 400 | Parámetro `from` ausente o no es entero |
| 404 | El bloque con ese índice no existe |
