# API Reference — VaultChain

Base URL: `http://localhost:8000`

Todos los endpoints que requieren autenticación esperan el header:
```
Authorization: Bearer <access_token>
```

---

## Módulo 1 — Autenticación (`/auth/`)

### POST /auth/register

Crea un usuario nuevo. Genera automáticamente un par de llaves RSA-2048 y ECDSA-P256 en el servidor; las privadas se entregan cifradas con la contraseña del usuario.

**Request**
```json
{
  "email": "alice@vaultchain.test",
  "display_name": "Alice",
  "password": "supersecret123"
}
```

**Response 201**
```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "email": "alice@vaultchain.test",
  "display_name": "Alice",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----",
  "created_at": "2026-05-24T12:00:00.000000Z"
}
```

**Errores**
| Código | Causa |
|--------|-------|
| 400 | Campos faltantes o contraseña < 8 chars |
| 409 | El email ya está registrado |

---

### POST /auth/login

Autentica al usuario. Si tiene MFA activo retorna `mfa_required: true` en lugar del token.

**Request**
```json
{
  "email": "alice@vaultchain.test",
  "password": "supersecret123"
}
```

**Response 200 — sin MFA**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "encrypted_private_key": "base64salt:base64nonce:base64ciphertext",
  "encrypted_ecdsa_private_key": "base64salt:base64nonce:base64ciphertext",
  "user": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "email": "alice@vaultchain.test",
    "display_name": "Alice",
    "mfa_enabled": false
  }
}
```

**Response 200 — con MFA activo**
```json
{
  "mfa_required": true,
  "email": "alice@vaultchain.test"
}
```

**Errores**
| Código | Causa |
|--------|-------|
| 400 | Campos faltantes |
| 401 | Credenciales inválidas |

---

### POST /auth/token/refresh

Obtiene un nuevo access token usando el refresh token.

**Request**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response 200**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Errores**
| Código | Causa |
|--------|-------|
| 401 | Refresh token expirado o inválido |

---

### GET /auth/users/

Lista todos los usuarios registrados. Pública — no requiere token.

**Response 200**
```json
{
  "users": [
    {
      "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "email": "alice@vaultchain.test",
      "display_name": "Alice"
    },
    {
      "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "email": "bob@vaultchain.test",
      "display_name": "Bob"
    }
  ]
}
```

---

### GET /auth/users/{user_id}/key

Retorna la llave pública RSA de un usuario en formato PEM. Pública — no requiere token.

**Response 200** — `Content-Type: application/x-pem-file`
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a2rwplBQLzHPZe5TNJF
...
-----END PUBLIC KEY-----
```

**Errores**
| Código | Causa |
|--------|-------|
| 404 | Usuario no encontrado |

---

## Módulo 1 — MFA (TOTP)

### POST /auth/mfa/enable

Genera el secreto TOTP y retorna el QR para registrar en el autenticador. Requiere token.

**Request** — body vacío

**Response 200**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "provisioning_uri": "otpauth://totp/VaultChain:alice@vaultchain.test?secret=JBSWY3DPEHPK3PXP&issuer=VaultChain",
  "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
}
```

---

### POST /auth/mfa/confirm

Confirma que el usuario escaneó el QR y verifica el primer código TOTP. Activa MFA en la cuenta. Requiere token.

**Request**
```json
{
  "totp_code": "123456"
}
```

**Response 200** — emite nuevos tokens con `mfa_enabled: true`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "encrypted_private_key": "base64salt:base64nonce:base64ciphertext",
  "encrypted_ecdsa_private_key": "base64salt:base64nonce:base64ciphertext",
  "user": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "email": "alice@vaultchain.test",
    "display_name": "Alice",
    "mfa_enabled": true
  }
}
```

**Errores**
| Código | Causa |
|--------|-------|
| 400 | Código TOTP inválido |

---

### POST /auth/mfa/verify

Segunda etapa del login cuando MFA está activo. No requiere token.

**Request**
```json
{
  "email": "alice@vaultchain.test",
  "totp_code": "123456"
}
```

**Response 200** — mismo formato que login completo

**Errores**
| Código | Causa |
|--------|-------|
| 400 | Campos faltantes o código incorrecto |
| 401 | Usuario no existe o MFA no activo |

---

### POST /auth/mfa/disable

Desactiva MFA. Requiere token y confirmar con contraseña.

**Request**
```json
{
  "password": "supersecret123"
}
```

**Response 200**
```json
{
  "message": "MFA disabled successfully"
}
```

---

## Módulo 2 — Mensajería cifrada (`/messages/`)

### POST /messages/

Envía un mensaje directo o grupal. El servidor cifra el plaintext con AES-256-GCM + RSA-OAEP para cada destinatario y registra la transacción en el blockchain. Requiere token.

**Request — mensaje directo**
```json
{
  "recipient_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "plaintext": "Hola Bob, este mensaje está cifrado.",
  "signature": "MEQCIBn...base64_ecdsa_signature..."
}
```

**Request — mensaje grupal**
```json
{
  "group_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "plaintext": "Reunión mañana a las 9.",
  "signature": "MEQCIBn...base64_ecdsa_signature..."
}
```

**Response 201 — mensaje directo**
```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "sender_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "recipient_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "created_at": "2026-05-24T12:05:00.000000Z"
}
```

**Response 201 — mensaje grupal**
```json
{
  "group_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "message_count": 3,
  "created_at": "2026-05-24T12:05:00.000000Z"
}
```

**Errores**
| Código | Causa |
|--------|-------|
| 400 | Falta `plaintext`, `signature`, o ambos/ningún destinatario |
| 403 | El remitente no es miembro del grupo |
| 404 | `recipient_id` o `group_id` no existe |

---

### GET /messages/{user_id}

Obtiene la bandeja de entrada del usuario autenticado. Solo puede leer sus propios mensajes. Requiere token.

**Response 200**
```json
{
  "messages": [
    {
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "sender_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "sender_name": "Alice",
      "sender_email": "alice@vaultchain.test",
      "recipient_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "group_id": null,
      "ciphertext": "base64encodedciphertext==",
      "encrypted_key": "base64encodedencryptedkey==",
      "nonce": "base64encodednonce==",
      "auth_tag": "base64encodedauthtag==",
      "signature": "MEQCIBn...base64_ecdsa_signature...",
      "has_signature": true,
      "signature_verified": true,
      "created_at": "2026-05-24T12:05:00.000000Z"
    }
  ]
}
```

**Errores**
| Código | Causa |
|--------|-------|
| 403 | El token no corresponde al `user_id` solicitado |

---

### POST /messages/{msg_id}/verify

Verifica la firma ECDSA de un mensaje. El cliente descifra primero localmente y envía el plaintext resultante. Requiere token.

**Request**
```json
{
  "plaintext": "Hola Bob, este mensaje está cifrado."
}
```

**Response 200 — firma válida**
```json
{
  "message_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "verified": true
}
```

**Response 200 — firma inválida**
```json
{
  "message_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "verified": false,
  "reason": "invalid_signature"
}
```

Valores de `reason`: `no_signature`, `no_ecdsa_key`, `invalid_signature`.

**Errores**
| Código | Causa |
|--------|-------|
| 403 | El token no corresponde al destinatario del mensaje |
| 404 | Mensaje no encontrado |

---

## Módulo 2 — Grupos (`/groups/`)

### POST /groups/

Crea un grupo de mensajería. El creador queda incluido automáticamente como miembro. Requiere token.

**Request**
```json
{
  "name": "Equipo Finanzas",
  "member_ids": [
    "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "b6b8d9e0-1234-5678-abcd-ef9876543210"
  ]
}
```

**Response 201**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "Equipo Finanzas",
  "created_at": "2026-05-24T12:10:00.000000Z",
  "members": [
    {
      "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "display_name": "Alice",
      "email": "alice@vaultchain.test",
      "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----"
    },
    {
      "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "display_name": "Bob",
      "email": "bob@vaultchain.test",
      "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----"
    }
  ]
}
```

**Errores**
| Código | Causa |
|--------|-------|
| 400 | `member_ids` vacío o nombre faltante |
| 404 | Alguno de los `member_ids` no existe |

---

### GET /groups/{group_id}

Retorna info del grupo incluyendo la llave pública RSA de cada miembro. Pública — no requiere token.

**Response 200**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "Equipo Finanzas",
  "created_at": "2026-05-24T12:10:00.000000Z",
  "members": [
    {
      "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "display_name": "Alice",
      "email": "alice@vaultchain.test",
      "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----"
    }
  ]
}
```

**Errores**
| Código | Causa |
|--------|-------|
| 404 | Grupo no encontrado |

---

## Módulo 3 — Firmas digitales (`/signatures/`)

### POST /signatures/verify/

Verifica la firma ECDSA de un mensaje a partir de su ID y el plaintext descifrado. Requiere token.

**Request**
```json
{
  "message_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "plaintext": "Hola Bob, este mensaje está cifrado."
}
```

**Response 200 — firma válida**
```json
{
  "verified": true,
  "message_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

**Response 200 — firma inválida**
```json
{
  "verified": false,
  "message_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "reason": "no_signature"
}
```

Valores de `reason`: `no_signature`, `no_ecdsa_key`.

**Errores**
| Código | Causa |
|--------|-------|
| 403 | El token no corresponde al destinatario del mensaje |
| 404 | Mensaje no encontrado |

---

## Módulo 3 — Blockchain (`/blockchain/`)

### GET /blockchain/

Retorna la cadena completa de bloques de auditoría. El bloque 0 es el génesis. Cada mensaje enviado genera un bloque nuevo automáticamente. Pública — no requiere token.

**Response 200**
```json
{
  "length": 3,
  "chain": [
    {
      "index": 0,
      "timestamp": "2026-05-24T12:00:00.000000Z",
      "sender_id": null,
      "recipient_id": null,
      "message_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "nonce": 0,
      "hash": "00003a1f2b8c..."
    },
    {
      "index": 1,
      "timestamp": "2026-05-24T12:05:00.000000Z",
      "sender_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "recipient_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "message_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "previous_hash": "00003a1f2b8c...",
      "nonce": 14302,
      "hash": "0000b8a9c1d2..."
    }
  ]
}
```

---

### GET /blockchain/verify/

Verifica la integridad completa de la cadena: hash interno de cada bloque y encadenamiento con el bloque anterior. Pública — no requiere token.

**Response 200 — cadena íntegra**
```json
{
  "valid": true,
  "length": 3,
  "detail": "All 3 blocks are valid."
}
```

**Response 200 — hash interno corrupto**
```json
{
  "valid": false,
  "failed_at_index": 2,
  "reason": "hash_mismatch",
  "detail": "Block 2: stored hash does not match computed hash."
}
```

**Response 200 — enlace roto entre bloques**
```json
{
  "valid": false,
  "failed_at_index": 2,
  "reason": "broken_link",
  "detail": "Block 2: previous_hash does not match hash of block 1."
}
```

---

### GET /blockchain/verify/from/?from={index}

Verifica la cadena desde el génesis hasta el bloque indicado. Útil para auditorías parciales. Pública — no requiere token.

**Query params**
| Param | Tipo | Descripción |
|-------|------|-------------|
| `from` | integer | Índice máximo del bloque a verificar (inclusive) |

**Ejemplo:** `GET /blockchain/verify/from/?from=5`

**Response 200 — válida**
```json
{
  "valid": true,
  "from_index": 5,
  "length": 6,
  "detail": "All 6 blocks up to index 5 are valid."
}
```

**Response 200 — inválida**
```json
{
  "valid": false,
  "from_index": 5,
  "failed_at_index": 3,
  "reason": "hash_mismatch",
  "detail": "Block 3: stored hash does not match computed hash."
}
```

**Errores**
| Código | Causa |
|--------|-------|
| 400 | Parámetro `from` ausente o no es entero |
| 404 | No existen bloques hasta el índice indicado |

---

## Resumen de autenticación

| Endpoint | Auth |
|----------|------|
| `POST /auth/register` | No |
| `POST /auth/login` | No |
| `POST /auth/token/refresh` | No |
| `POST /auth/mfa/verify` | No |
| `GET /auth/users/` | No |
| `GET /auth/users/{id}/key` | No |
| `POST /auth/mfa/enable` | Sí |
| `POST /auth/mfa/confirm` | Sí |
| `POST /auth/mfa/disable` | Sí |
| `POST /messages/` | Sí |
| `GET /messages/{user_id}` | Sí |
| `POST /messages/{id}/verify` | Sí |
| `POST /groups/` | Sí |
| `GET /groups/{id}` | No |
| `POST /signatures/verify/` | Sí |
| `GET /blockchain/` | No |
| `GET /blockchain/verify/` | No |
| `GET /blockchain/verify/from/` | No |

Los tokens expiran en **1 hora**. Usar `POST /auth/token/refresh` para renovar sin re-autenticar.
