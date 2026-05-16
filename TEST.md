# MFA Test Flow — cURL

Base URL: `http://localhost:8000`

---

## 1. Registrar usuario

```bash
curl -s -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"mfa@test.com","display_name":"MFA User","password":"SecurePass123!"}' | python3 -m json.tool
```

---

## 2. Login sin MFA activo (debe devolver JWT directo)

```bash
curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"mfa@test.com","password":"SecurePass123!"}' | python3 -m json.tool
```

Guarda el `access_token`:
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"mfa@test.com","password":"SecurePass123!"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo $TOKEN
```

---

## 3. Activar MFA — genera secreto TOTP y QR

```bash
curl -s -X POST http://localhost:8000/auth/mfa/enable \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" | python3 -m json.tool
```

Guarda el `secret`:
```bash
SECRET=$(curl -s -X POST http://localhost:8000/auth/mfa/enable \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" | python3 -c "import sys,json; print(json.load(sys.stdin)['secret'])")
echo $SECRET
```

> El campo `qr_code` es un `data:image/png;base64,...` — pégalo en el navegador para ver el QR y escanearlo con Google Authenticator.

---

## 4. Generar código TOTP actual (sin app, solo para pruebas)

```bash
python3 -c "import pyotp; print(pyotp.TOTP('$SECRET').now())"
```

---

## 5. Login con MFA activo (debe devolver mfa_required en lugar de JWT)

```bash
curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"mfa@test.com","password":"SecurePass123!"}' | python3 -m json.tool
```

Respuesta esperada:
```json
{
  "mfa_required": true,
  "email": "mfa@test.com"
}
```

---

## 6. Verificar código TOTP y obtener JWT

```bash
CODE=$(python3 -c "import pyotp; print(pyotp.TOTP('$SECRET').now())")

curl -s -X POST http://localhost:8000/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"mfa@test.com\",\"totp_code\":\"$CODE\"}" | python3 -m json.tool
```

Respuesta esperada: `access_token`, `refresh_token`, `user`.

---

## 7. Casos de error

**Sin JWT en /mfa/enable:**
```bash
curl -s -X POST http://localhost:8000/auth/mfa/enable \
  -H "Content-Type: application/json" | python3 -m json.tool
# 401 Missing or invalid Authorization header
```

**Código TOTP incorrecto:**
```bash
curl -s -X POST http://localhost:8000/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{"email":"mfa@test.com","totp_code":"000000"}' | python3 -m json.tool
# 401 Invalid or expired TOTP code
```

**Campos faltantes en /mfa/verify:**
```bash
curl -s -X POST http://localhost:8000/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{"email":"mfa@test.com"}' | python3 -m json.tool
# 400 email and totp_code are required
```

**Usuario sin MFA intentando verificar:**
```bash
curl -s -X POST http://localhost:8000/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{"email":"otro@test.com","totp_code":"123456"}' | python3 -m json.tool
# 400 MFA is not enabled for this user  (si el usuario existe sin totp_secret)
# 401 Invalid credentials               (si el usuario no existe)
```
