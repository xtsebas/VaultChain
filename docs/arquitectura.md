# Arquitectura de VaultChain

## Descripcion general

VaultChain es un sistema de mensajeria segura compuesto por cuatro capas criptograficas que se construyen de forma incremental.

## Capas del sistema

```
[Capa 4] API REST + Frontend     →  JWT, MFA (TOTP), interfaz web
[Capa 3] Firmas + Blockchain     →  ECDSA, SHA-256, cadena inmutable
[Capa 2] Cifrado Hibrido         →  AES-256-GCM + RSA-OAEP
[Capa 1] Gestion de Identidad    →  bcrypt/Argon2, pares de llaves RSA/ECC
```

## Flujo de un mensaje

1. Remitente obtiene la llave publica del destinatario
2. Genera clave AES-256 efimera
3. Cifra el mensaje con AES-256-GCM
4. Cifra la clave AES con RSA-OAEP usando la llave publica del destinatario
5. Firma el hash SHA-256 del plaintext con su llave privada ECDSA
6. Envia ciphertext + encrypted_key + nonce + tag + firma
7. Se registra automaticamente una transaccion en el blockchain
8. Destinatario descifra la clave AES con su llave privada
9. Descifra el mensaje y verifica la firma

## Componentes

- **Django REST**: API backend
- **PostgreSQL**: Base de datos principal
- **React**: Interfaz web
- **Docker Compose**: Orquestacion de servicios

## Decisiones de diseño

_Por completar durante el desarrollo._