# Errores encontrados durante el desarrollo

Registro de problemas que surgieron durante la implementación y cómo se resolvieron.

## 1. `select_for_update()` falla en SQLite

**Síntoma:** El test de concurrencia `ConcurrentAppendTest` lanzaba `OperationalError: database table is locked`.

**Causa:** `select_for_update()` requiere bloqueo a nivel de fila, que solo PostgreSQL soporta. SQLite bloquea a nivel de archivo y bajo concurrencia de threads lanza el error.

**Solución:** Se marcó el test con `@skipIf` cuando el engine es SQLite. El test corre correctamente en el entorno Docker con PostgreSQL.

---

## 2. `TransactionTestCase` no recrea las tablas

**Síntoma:** `OperationalError: table "blockchain" already exists` al correr el test de concurrencia.

**Causa:** `TransactionTestCase` vacía los datos entre tests pero **no** borra el esquema. El `setUp` intentaba crear la tabla con `schema_editor.create_model()` cuando ya existía.

**Solución:** Remover la llamada a `create_model()` y solo insertar el genesis block directamente.

---

## 3. Vista `get_chain` mezclaba `.values()` con instancias ORM

**Síntoma:** `TypeError: 'Block' object is not subscriptable` al llamar `GET /blockchain/`.

**Causa:** El queryset se calculaba con `.values()` para el `len()`, pero el list comprehension iteraba sobre `Block.objects.order_by('index')` que retorna objetos, no dicts.

**Solución:** Hacer una sola query y guardarla en una variable:
```python
blocks = list(Block.objects.order_by('index'))
```

---
## 4. Test `broken_link` disparaba `hash_mismatch` primero

**Síntoma:** El test que adulteraba `previous_hash` esperaba `reason: broken_link` pero recibía `reason: hash_mismatch`.

**Causa:** Al cambiar `previous_hash` sin recalcular `hash`, el bloque quedaba internamente inconsistente. El endpoint detecta primero `hash_mismatch` antes de revisar el enlace.

**Solución:** En el test, después de cambiar `previous_hash`, recalcular y guardar el `hash` del bloque para que sea internamente consistente pero el enlace al bloque anterior esté roto.

---

## 5. `ecdsa_public_key` no está en la respuesta de `/auth/register`

**Síntoma:** `KeyError: 'ecdsa_public_key'` en el `setUp` de los tests E2E.

**Causa:** `RegisterView` retorna solo `id`, `email`, `display_name`, `public_key` (RSA) y `created_at`. La clave ECDSA pública no se incluye en la respuesta de registro; el cliente la recibe al hacer login.

**Solución:** Verificar `ecdsa_public_key` directamente en la BD con `User.objects.get(id=...)`.

---
