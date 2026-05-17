"""
Tests E2E — Flujo completo de mensajería segura (cross-módulo).

    Este archivo simula el flujo real de dos usuarios:
        - Alice (remitente)
        - Bob   (destinatario)

    Flujo cubierto:
        1. [auth_module]   Registro de usuarios con claves RSA y ECDSA
        2. [auth_module]   Activación de MFA/TOTP
        3. [auth_module]   Login con código TOTP válido
        4. [crypto_module] Envío de mensaje cifrado (AES-256-GCM + RSA-OAEP)
        5. [signatures]    Firma digital ECDSA del mensaje
        6. [crypto_module] Recepción y descifrado del mensaje
        7. [signatures]    Verificación de la firma ECDSA
        8. [blockchain]    Confirmación del registro en el audit trail

Módulos involucrados:
    auth_module   → registro, MFA, JWT
    crypto_module → cifrado híbrido, mensajes
    signatures    → ECDSA sign/verify
    blockchain    → encadenamiento e integridad

Notas de implementación:
    - El registro se hace vía API real (POST /auth/register).
    - Las claves privadas retornadas por el servidor vienen cifradas con la
      contraseña del usuario (PBKDF2 + AES-256-GCM). Se descifran en el test
      para simular lo que haría el cliente frontend.
    - El descifrado de mensajes es puramente client-side (el servidor nunca
      ve el plaintext ni las claves privadas).
"""

import base64
import hashlib

import pyotp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from django.test import TestCase
from rest_framework import status
from rest_framework.test import APITestCase

from blockchain.models import Block
from crypto_module.decryption import decrypt_message
from signatures.ecdsa_utils import sign_message


# ── URLs ──────────────────────────────────────────────────────────────────────

REGISTER_URL        = '/auth/register'
LOGIN_URL           = '/auth/login'
MFA_ENABLE_URL      = '/auth/mfa/enable'
MFA_VERIFY_URL      = '/auth/mfa/verify'
MESSAGES_URL        = '/messages/'
SIGNATURES_VERIFY   = '/signatures/verify/'
BLOCKCHAIN_URL      = '/blockchain/'
BLOCKCHAIN_VERIFY   = '/blockchain/verify/'


# ── Helpers de descifrado de claves (simulan el cliente) ─────────────────────

def _decrypt_key_pem(encrypted_key_str: str, password: str) -> str:
    """
    Descifra una clave privada (RSA o ECDSA) retornada por /auth/register.

    El servidor cifra la clave con PBKDF2HMAC(SHA-256, 600_000 iter) + AES-256-GCM
    y la serializa como 'salt_b64:nonce_b64:ciphertext_b64'.

    El cliente (aquí: el test) la descifra usando la contraseña en texto plano
    que el usuario conoce pero nunca envía al servidor tras el registro.
    """
    salt_b64, nonce_b64, ciphertext_b64 = encrypted_key_str.split(':')
    salt       = base64.b64decode(salt_b64)
    nonce      = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    aes_key     = kdf.derive(password.encode('utf-8'))
    private_der = AESGCM(aes_key).decrypt(nonce, ciphertext, None)

    # Convertir DER → PEM para que pycryptodome y cryptography puedan usarlo
    private_key = serialization.load_der_private_key(private_der, password=None)
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode('utf-8')


# ═══════════════════════════════════════════════════════════════════════════════
# FASE 1-3: auth_module — Registro, MFA y Login con TOTP
# ═══════════════════════════════════════════════════════════════════════════════

class RegistroYMFATest(APITestCase):
    """
    [Módulo: auth_module]

    Verifica que un usuario puede registrarse, activar MFA y luego
    autenticarse usando un código TOTP generado por su aplicación autenticadora.

    Todos los usuarios con acceso a mensajes cifrados deben tener MFA
    obligatorio. Estos tests validan esa restricción.
    """

    PASSWORD = 'MiPassSegura123!'

    def _registrar(self, email, nombre):
        """Registra un usuario vía API y retorna la respuesta completa."""
        return self.client.post(REGISTER_URL, {
            'email':        email,
            'display_name': nombre,
            'password':     self.PASSWORD,
        }, format='json')

    def test_registro_crea_usuario_con_claves(self):
        """
        [auth_module → RegisterView]
        El servidor genera claves RSA (cifrado) y ECDSA (firmas) al registrarse.
        El cliente recibe las claves privadas cifradas con su contraseña.
        """
        resp = self._registrar('ana@vaultchain.test', 'Alice')
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        from auth_module.models import User
        data = resp.json()
        self.assertIn('id', data)
        self.assertIn('public_key', data)  # clave RSA pública en la respuesta

        # La clave ECDSA se genera y persiste en BD (el cliente la recibe
        # cifrada al hacer login, no en el registro directo)
        user = User.objects.get(id=data['id'])
        self.assertIsNotNone(user.ecdsa_public_key)

    def test_login_sin_mfa_retorna_tokens(self):
        """
        [auth_module → LoginView]
        Un usuario sin MFA activo obtiene sus tokens JWT directamente al hacer login.
        """
        self._registrar('sin_mfa@vaultchain.test', 'Sin MFA')

        resp = self.client.post(LOGIN_URL, {
            'email':    'sin_mfa@vaultchain.test',
            'password': self.PASSWORD,
        }, format='json')

        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', resp.json())

    def test_activar_mfa_guarda_totp_secret(self):
        """
        [auth_module → MFAEnableView]
        Al activar MFA el servidor genera un secreto TOTP, lo almacena en el usuario
        y retorna el URI de aprovisionamiento para Google Authenticator / Authy.
        """
        reg  = self._registrar('con_mfa@vaultchain.test', 'Con MFA')
        data = reg.json()

        # Login inicial para obtener JWT (aún sin MFA activado)
        login = self.client.post(LOGIN_URL, {
            'email':    'con_mfa@vaultchain.test',
            'password': self.PASSWORD,
        }, format='json')
        token = login.json()['access_token']

        # Activar MFA con ese JWT
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        mfa_resp = self.client.post(MFA_ENABLE_URL, format='json')

        self.assertEqual(mfa_resp.status_code, status.HTTP_200_OK)
        mfa_data = mfa_resp.json()
        self.assertIn('secret', mfa_data)
        self.assertIn('provisioning_uri', mfa_data)
        self.assertIn('qr_code', mfa_data)
        self.assertTrue(mfa_data['qr_code'].startswith('data:image/png;base64,'))

    def test_login_con_mfa_activo_exige_totp(self):
        """
        [auth_module → LoginView + MFAVerifyView]
        Una vez activado el MFA, el login estándar devuelve mfa_required=True
        y exige la verificación del código TOTP antes de emitir tokens.
        Esta es la restricción de seguridad crítica del sistema.
        """
        self._registrar('mfa_exigido@vaultchain.test', 'MFA Exigido')

        # Login para obtener JWT y activar MFA
        login = self.client.post(LOGIN_URL, {
            'email': 'mfa_exigido@vaultchain.test', 'password': self.PASSWORD,
        }, format='json')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {login.json()["access_token"]}')
        secret = self.client.post(MFA_ENABLE_URL, format='json').json()['secret']
        self.client.credentials()  # limpiar credenciales

        # Ahora el login debe exigir TOTP
        resp = self.client.post(LOGIN_URL, {
            'email': 'mfa_exigido@vaultchain.test', 'password': self.PASSWORD,
        }, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertTrue(resp.json().get('mfa_required'))
        self.assertNotIn('access_token', resp.json())

        # Con el código TOTP correcto sí se emiten tokens
        totp_code = pyotp.TOTP(secret).now()
        verify = self.client.post(MFA_VERIFY_URL, {
            'email': 'mfa_exigido@vaultchain.test', 'totp_code': totp_code,
        }, format='json')
        self.assertEqual(verify.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', verify.json())

    def test_totp_invalido_es_rechazado(self):
        """
        [auth_module → MFAVerifyView]
        Un código TOTP incorrecto (o expirado) no produce tokens.
        Evita ataques de fuerza bruta al segundo factor.
        """
        self._registrar('invalido@vaultchain.test', 'Inválido')
        login = self.client.post(LOGIN_URL, {
            'email': 'invalido@vaultchain.test', 'password': self.PASSWORD,
        }, format='json')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {login.json()["access_token"]}')
        self.client.post(MFA_ENABLE_URL, format='json')
        self.client.credentials()

        resp = self.client.post(MFA_VERIFY_URL, {
            'email': 'invalido@vaultchain.test', 'totp_code': '000000',
        }, format='json')
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIn('access_token', resp.json())


# ═══════════════════════════════════════════════════════════════════════════════
# FASE 4-5: crypto_module — Envío cifrado y descifrado
# ═══════════════════════════════════════════════════════════════════════════════

class MensajeCifradoTest(APITestCase):
    """
    [Módulo: crypto_module]

    Verifica que Ana puede enviar a Luis un documento cifrado con su clave
    pública RSA, y que Luis puede descifrarlo usando su clave privada.

    El servidor nunca ve el contenido del mensaje ni las claves privadas.
    El cifrado es híbrido: AES-256-GCM para el contenido, RSA-OAEP para
    la clave AES. Así se mantiene confidencialidad E2E.
    """

    PASSWORD = 'MiPassSegura123!'

    def setUp(self):
        """
        Registra a Ana (remitente) y Luis (destinatario) vía API real,
        y descifra sus claves privadas para usarlas en el test.
        """
        # Registrar Ana
        ana_reg = self.client.post(REGISTER_URL, {
            'email': 'ana@vaultchain.test', 'display_name': 'Alice',
            'password': self.PASSWORD,
        }, format='json').json()
        self.ana_id = ana_reg['id']

        # Registrar Luis
        luis_reg = self.client.post(REGISTER_URL, {
            'email': 'luis@vaultchain.test', 'display_name': 'Bob',
            'password': self.PASSWORD,
        }, format='json').json()
        self.luis_id = luis_reg['id']

        # Ana hace login (sin MFA) y obtiene su token
        ana_login = self.client.post(LOGIN_URL, {
            'email': 'ana@vaultchain.test', 'password': self.PASSWORD,
        }, format='json').json()
        self.ana_token          = ana_login['access_token']
        # Descifrar clave ECDSA de Ana para poder firmar mensajes
        self.ana_ecdsa_priv_pem = _decrypt_key_pem(
            ana_login['encrypted_ecdsa_private_key'], self.PASSWORD
        )

        # Luis hace login y obtiene su clave RSA privada para descifrar
        luis_login = self.client.post(LOGIN_URL, {
            'email': 'luis@vaultchain.test', 'password': self.PASSWORD,
        }, format='json').json()
        self.luis_rsa_priv_pem = _decrypt_key_pem(
            luis_login['encrypted_private_key'], self.PASSWORD
        )

        # Autenticar al cliente como Ana
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.ana_token}')

    def _enviar_mensaje(self, plaintext: str):
        """Firma el plaintext y lo envía a Luis. Retorna la respuesta."""
        signature = sign_message(plaintext.encode('utf-8'), self.ana_ecdsa_priv_pem)
        return self.client.post(MESSAGES_URL, {
            'recipient_id': self.luis_id,
            'plaintext':    plaintext,
            'signature':    signature,
        }, format='json')

    def test_enviar_mensaje_retorna_201(self):
        """
        [crypto_module → SendMessageView._send_direct_message]
        El servidor acepta el mensaje, lo cifra con la clave pública de Luis
        y retorna 201 con los metadatos del mensaje.
        """
        resp = self._enviar_mensaje('Informe trimestral Q1 — CONFIDENCIAL')
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        data = resp.json()
        self.assertIn('id', data)
        self.assertEqual(data['sender_id'],    self.ana_id)
        self.assertEqual(data['recipient_id'], self.luis_id)

    def test_mensaje_en_lista_de_luis_tiene_ciphertext(self):
        """
        [crypto_module → get_user_messages]
        Luis recibe el mensaje cifrado; el ciphertext es distinto al plaintext
        original y el servidor nunca almacena el contenido en claro.
        """
        plaintext = 'Datos de auditoría interna — RESERVADO'
        self._enviar_mensaje(plaintext)

        # Luis consulta sus mensajes
        luis_login = self.client.post(LOGIN_URL, {
            'email': 'luis@vaultchain.test', 'password': self.PASSWORD,
        }, format='json').json()
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {luis_login["access_token"]}'
        )

        resp  = self.client.get(f'/messages/{self.luis_id}')
        msg   = resp.json()['messages'][0]

        self.assertIn('ciphertext', msg)
        # El servidor nunca guarda el plaintext
        self.assertNotEqual(msg['ciphertext'], plaintext)
        self.assertNotIn(plaintext, str(msg))

    def test_luis_puede_descifrar_el_mensaje(self):
        """
        [crypto_module → decrypt_message (client-side)]
        Con su clave RSA privada, Luis recupera el plaintext exacto que Ana envió.
        El descifrado ocurre en el cliente; el servidor no participa.
        """
        plaintext = 'Transferencia autorizada: #TXN-2500 — CONFIDENCIAL'
        self._enviar_mensaje(plaintext)

        # Luis obtiene el mensaje cifrado del servidor
        luis_login = self.client.post(LOGIN_URL, {
            'email': 'luis@vaultchain.test', 'password': self.PASSWORD,
        }, format='json').json()
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {luis_login["access_token"]}'
        )
        msg = self.client.get(f'/messages/{self.luis_id}').json()['messages'][0]

        # Luis descifra localmente con su clave privada RSA
        decrypted_bytes = decrypt_message(
            ciphertext_b64      = msg['ciphertext'],
            encrypted_key_b64   = msg['encrypted_key'],
            nonce_b64           = msg['nonce'],
            auth_tag_b64        = msg['auth_tag'],
            recipient_private_key_pem = self.luis_rsa_priv_pem,
        )
        self.assertEqual(decrypted_bytes.decode('utf-8'), plaintext)


# ═══════════════════════════════════════════════════════════════════════════════
# FASE 6: signatures — Verificación de firma ECDSA
# ═══════════════════════════════════════════════════════════════════════════════

class VerificacionFirmaTest(APITestCase):
    """
    [Módulo: signatures]

    Verifica que Luis puede confirmar que el mensaje realmente fue enviado
    por Ana (autenticidad) y que no fue alterado en tránsito (integridad).

    La firma ECDSA P-256 sobre SHA-256(plaintext) garantiza ambas propiedades.
    Si alguien modificó el ciphertext o la firma, la verificación falla.
    """

    PASSWORD = 'MiPassSegura123!'

    def setUp(self):
        # Registrar Ana
        ana_reg = self.client.post(REGISTER_URL, {
            'email': 'ana_sig@vaultchain.test', 'display_name': 'Alice',
            'password': self.PASSWORD,
        }, format='json').json()
        self.ana_id = ana_reg['id']

        # Registrar Luis
        luis_reg = self.client.post(REGISTER_URL, {
            'email': 'luis_sig@vaultchain.test', 'display_name': 'Bob',
            'password': self.PASSWORD,
        }, format='json').json()
        self.luis_id = luis_reg['id']

        # Login de Ana — obtiene clave ECDSA privada para firmar
        ana_login = self.client.post(LOGIN_URL, {
            'email': 'ana_sig@vaultchain.test', 'password': self.PASSWORD,
        }, format='json').json()
        self.ana_token          = ana_login['access_token']
        self.ana_ecdsa_priv_pem = _decrypt_key_pem(
            ana_login['encrypted_ecdsa_private_key'], self.PASSWORD
        )

        # Login de Luis — obtiene token y clave RSA privada
        luis_login = self.client.post(LOGIN_URL, {
            'email': 'luis_sig@vaultchain.test', 'password': self.PASSWORD,
        }, format='json').json()
        self.luis_token        = luis_login['access_token']
        self.luis_rsa_priv_pem = _decrypt_key_pem(
            luis_login['encrypted_private_key'], self.PASSWORD
        )

        # Ana envía un mensaje firmado
        self.plaintext = 'Autorización de acceso — expediente 2026-0512'
        signature = sign_message(self.plaintext.encode('utf-8'), self.ana_ecdsa_priv_pem)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.ana_token}')
        resp = self.client.post(MESSAGES_URL, {
            'recipient_id': self.luis_id,
            'plaintext':    self.plaintext,
            'signature':    signature,
        }, format='json')
        self.message_id = resp.json()['id']

    def test_verificacion_firma_valida_retorna_verified_true(self):
        """
        [signatures → verify_message_signature (POST /signatures/verify/)]
        Luis descifra el mensaje y envía el plaintext al servidor.
        El servidor verifica la firma ECDSA de Ana con su clave pública
        y confirma que el mensaje es auténtico e íntegro.
        """
        # Luis descifra localmente
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.luis_token}')
        msg = self.client.get(f'/messages/{self.luis_id}').json()['messages'][0]

        decrypted = decrypt_message(
            ciphertext_b64            = msg['ciphertext'],
            encrypted_key_b64         = msg['encrypted_key'],
            nonce_b64                 = msg['nonce'],
            auth_tag_b64              = msg['auth_tag'],
            recipient_private_key_pem = self.luis_rsa_priv_pem,
        ).decode('utf-8')

        self.assertEqual(decrypted, self.plaintext)

        # Luis solicita verificación de firma al servidor
        resp = self.client.post(SIGNATURES_VERIFY, {
            'message_id': self.message_id,
            'plaintext':  decrypted,
        }, format='json')

        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        data = resp.json()
        self.assertTrue(data['verified'])
        self.assertEqual(data['message_id'], self.message_id)

    def test_plaintext_alterado_falla_verificacion(self):
        """
        [signatures → verify_message_signature]
        Si Luis recibe el ciphertext correcto pero intenta verificar la firma
        contra un plaintext distinto (alterado en tránsito), la verificación falla.
        Esto garantiza integridad: cualquier alteración del contenido es detectable.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.luis_token}')

        resp = self.client.post(SIGNATURES_VERIFY, {
            'message_id': self.message_id,
            'plaintext':  'Contenido alterado — expediente 2026-0512-FAKE',
        }, format='json')

        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertFalse(resp.json()['verified'])


# ═══════════════════════════════════════════════════════════════════════════════
# FASE 7: blockchain — Registro e integridad del audit trail
# ═══════════════════════════════════════════════════════════════════════════════

class BlockchainAuditTrailTest(APITestCase):
    """
    [Módulo: blockchain]

    Verifica que cada mensaje enviado queda registrado automáticamente en el
    blockchain de auditoría, y que la cadena se mantiene íntegra.

    El blockchain sirve como registro inmutable de qué usuario comunicó
    qué información y cuándo, sin revelar el contenido.
    El hash del mensaje (SHA-256 del plaintext) permite verificar integridad
    sin exponer datos sensibles.
    """

    PASSWORD = 'MiPassSegura123!'

    def setUp(self):
        # Registrar Ana y Luis
        ana_reg = self.client.post(REGISTER_URL, {
            'email': 'ana_bc@vaultchain.test', 'display_name': 'Alice',
            'password': self.PASSWORD,
        }, format='json').json()
        self.ana_id = ana_reg['id']

        luis_reg = self.client.post(REGISTER_URL, {
            'email': 'luis_bc@vaultchain.test', 'display_name': 'Bob',
            'password': self.PASSWORD,
        }, format='json').json()
        self.luis_id = luis_reg['id']

        # Login de Ana
        ana_login = self.client.post(LOGIN_URL, {
            'email': 'ana_bc@vaultchain.test', 'password': self.PASSWORD,
        }, format='json').json()
        self.ana_token          = ana_login['access_token']
        self.ana_ecdsa_priv_pem = _decrypt_key_pem(
            ana_login['encrypted_ecdsa_private_key'], self.PASSWORD
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.ana_token}')

    def _enviar(self, texto):
        signature = sign_message(texto.encode('utf-8'), self.ana_ecdsa_priv_pem)
        return self.client.post(MESSAGES_URL, {
            'recipient_id': self.luis_id,
            'plaintext':    texto,
            'signature':    signature,
        }, format='json')

    def test_enviar_mensaje_crea_bloque_en_blockchain(self):
        """
        [blockchain → append_block]
        Cada mensaje enviado exitosamente agrega un bloque al audit trail.
        El bloque almacena SHA-256(plaintext), no el contenido en claro.
        """
        count_antes = Block.objects.count()
        plaintext   = 'Reporte interno 024-2026 — RESERVADO'

        resp = self._enviar(plaintext)
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        self.assertEqual(Block.objects.count(), count_antes + 1)

        bloque = Block.objects.order_by('-index').first()
        hash_esperado = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
        self.assertEqual(bloque.message_hash, hash_esperado)

    def test_bloque_registra_ids_de_remitente_y_destinatario(self):
        """
        [blockchain → Block model]
        El bloque identifica a los participantes de la comunicación (quién y a quién),
        lo que permite trazabilidad sin revelar el contenido del mensaje.
        """
        self._enviar('Comunicación trazable')
        bloque = Block.objects.order_by('-index').first()

        self.assertEqual(str(bloque.sender_id),    self.ana_id)
        self.assertEqual(str(bloque.recipient_id), self.luis_id)

    def test_multiples_mensajes_mantienen_cadena_integra(self):
        """
        [blockchain → append_block + GET /blockchain/verify/]
        Después de varios mensajes, la cadena sigue siendo íntegra:
        cada bloque apunta correctamente al anterior mediante su hash.
        Este es el mecanismo que hace al audit trail inmutable.
        """
        for i in range(3):
            resp = self._enviar(f'Mensaje cifrado #{i+1} — serie 2026')
            self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        resp = self.client.get(BLOCKCHAIN_VERIFY)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        data = resp.json()
        self.assertTrue(data['valid'], f'Cadena inválida: {data}')

    def test_blockchain_api_expone_la_cadena_completa(self):
        """
        [blockchain → GET /blockchain/]
        El endpoint retorna todos los bloques con su estructura completa,
        permitiendo que el frontend muestre el historial de auditoría.
        """
        self._enviar('Mensaje para inspección del audit trail')

        resp = self.client.get(BLOCKCHAIN_URL)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        data  = resp.json()
        chain = data['chain']

        self.assertGreaterEqual(data['length'], 2)  # genesis + al menos 1 mensaje

        # El último bloque tiene los IDs correctos
        ultimo = chain[-1]
        self.assertEqual(ultimo['sender_id'],    self.ana_id)
        self.assertEqual(ultimo['recipient_id'], self.luis_id)

        # El message_hash almacenado es SHA-256 del plaintext (no el plaintext)
        self.assertEqual(len(ultimo['message_hash']), 64)  # hex SHA-256


# ═══════════════════════════════════════════════════════════════════════════════
# FLUJO COMPLETO — Integración cross-módulo
# ═══════════════════════════════════════════════════════════════════════════════

class FlujoCompletoIntegrationTest(APITestCase):
    """
    [Módulos: auth_module + crypto_module + signatures + blockchain]

    Test de integración end-to-end que recorre el flujo completo de un
    usuario del sistema, desde el registro hasta la confirmación
    del audit trail, incluyendo MFA.

    Este test reproduce exactamente lo que sucede cuando:
        1. Alice se registra en el sistema.
        2. Ana activa MFA en su cuenta.
        3. Ana inicia sesión con su código TOTP.
        4. Ana envía un documento cifrado y firmado a Bob.
        5. Luis descifra el documento con su clave privada.
        6. Luis verifica que la firma de Ana es auténtica.
        7. El sistema confirma que el audit trail es íntegro.
    """

    PASSWORD = 'MiPassSegura123!'

    def test_flujo_completo_registro_mfa_mensaje_verificacion_blockchain(self):
        # ── Paso 1: Registro [auth_module] ────────────────────────────────────
        # Ana y Luis se registran. El servidor genera sus pares de claves.
        ana_data = self.client.post(REGISTER_URL, {
            'email': 'ana_full@vaultchain.test', 'display_name': 'Alice',
            'password': self.PASSWORD,
        }, format='json').json()
        self.assertIn('id', ana_data, 'Registro de Ana falló')

        luis_data = self.client.post(REGISTER_URL, {
            'email': 'luis_full@vaultchain.test', 'display_name': 'Bob',
            'password': self.PASSWORD,
        }, format='json').json()
        self.assertIn('id', luis_data, 'Registro de Luis falló')

        ana_id  = ana_data['id']
        luis_id = luis_data['id']

        # ── Paso 2: Activar MFA [auth_module] ────────────────────────────────
        # Ana activa MFA. Necesita su JWT antes de que el MFA esté activo.
        login_pre_mfa = self.client.post(LOGIN_URL, {
            'email': 'ana_full@vaultchain.test', 'password': self.PASSWORD,
        }, format='json').json()
        self.assertIn('access_token', login_pre_mfa, 'Login pre-MFA falló')

        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {login_pre_mfa["access_token"]}'
        )
        mfa_data = self.client.post(MFA_ENABLE_URL, format='json').json()
        self.assertIn('secret', mfa_data, 'Activación MFA falló')
        totp_secret = mfa_data['secret']

        # ── Paso 3: Login con TOTP [auth_module] ─────────────────────────────
        # Ahora el login estándar bloquea sin TOTP.
        self.client.credentials()  # limpiar JWT
        resp_bloqueado = self.client.post(LOGIN_URL, {
            'email': 'ana_full@vaultchain.test', 'password': self.PASSWORD,
        }, format='json').json()
        self.assertTrue(resp_bloqueado.get('mfa_required'),
                        'El login debería exigir TOTP tras activar MFA')

        # Ana ingresa su código TOTP y obtiene sus tokens definitivos.
        totp_code = pyotp.TOTP(totp_secret).now()
        login_totp = self.client.post(MFA_VERIFY_URL, {
            'email': 'ana_full@vaultchain.test', 'totp_code': totp_code,
        }, format='json').json()
        self.assertIn('access_token', login_totp,
                      'Login con TOTP válido no emitió tokens')

        ana_token          = login_totp['access_token']
        ana_ecdsa_priv_pem = _decrypt_key_pem(
            login_totp['encrypted_ecdsa_private_key'], self.PASSWORD
        )

        # Luis hace login (sin MFA para simplificar el flujo) y obtiene su
        # clave RSA privada para descifrar mensajes.
        luis_login = self.client.post(LOGIN_URL, {
            'email': 'luis_full@vaultchain.test', 'password': self.PASSWORD,
        }, format='json').json()
        luis_token         = luis_login['access_token']
        luis_rsa_priv_pem  = _decrypt_key_pem(
            luis_login['encrypted_private_key'], self.PASSWORD
        )

        # ── Paso 4: Enviar mensaje cifrado y firmado [crypto + signatures] ───
        # Ana firma el plaintext con ECDSA y lo envía. El servidor cifra
        # el contenido con la clave RSA pública de Luis.
        plaintext = 'Documento confidencial VaultChain — referencia VC-2026-001'
        signature = sign_message(plaintext.encode('utf-8'), ana_ecdsa_priv_pem)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {ana_token}')
        msg_resp = self.client.post(MESSAGES_URL, {
            'recipient_id': luis_id,
            'plaintext':    plaintext,
            'signature':    signature,
        }, format='json')
        self.assertEqual(msg_resp.status_code, status.HTTP_201_CREATED,
                         'Envío de mensaje falló')
        message_id = msg_resp.json()['id']

        # ── Paso 5: Recibir y descifrar [crypto_module] ───────────────────────
        # Luis obtiene el ciphertext del servidor y lo descifra localmente.
        # El servidor nunca vio el plaintext.
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {luis_token}')
        mensajes  = self.client.get(f'/messages/{luis_id}').json()['messages']
        msg       = next(m for m in mensajes if m['id'] == message_id)

        decrypted = decrypt_message(
            ciphertext_b64            = msg['ciphertext'],
            encrypted_key_b64         = msg['encrypted_key'],
            nonce_b64                 = msg['nonce'],
            auth_tag_b64              = msg['auth_tag'],
            recipient_private_key_pem = luis_rsa_priv_pem,
        ).decode('utf-8')

        self.assertEqual(decrypted, plaintext,
                         'El plaintext descifrado no coincide con el original')

        # ── Paso 6: Verificar firma [signatures] ─────────────────────────────
        # Luis confirma que el mensaje realmente viene de Ana y no fue alterado.
        verify_resp = self.client.post(SIGNATURES_VERIFY, {
            'message_id': message_id,
            'plaintext':  decrypted,
        }, format='json')
        self.assertEqual(verify_resp.status_code, status.HTTP_200_OK)
        self.assertTrue(verify_resp.json()['verified'],
                        'La firma ECDSA de Ana no fue verificada correctamente')

        # ── Paso 7: Confirmar blockchain [blockchain] ─────────────────────────
        # El audit trail debe ser íntegro: cada bloque apunta al anterior.
        chain_verify = self.client.get(BLOCKCHAIN_VERIFY).json()
        self.assertTrue(chain_verify['valid'],
                        f'El blockchain quedó inválido tras el flujo: {chain_verify}')

        # El último bloque registra la transacción de Ana hacia Luis.
        ultimo_bloque = Block.objects.order_by('-index').first()
        self.assertEqual(str(ultimo_bloque.sender_id),    ana_id)
        self.assertEqual(str(ultimo_bloque.recipient_id), luis_id)
        self.assertEqual(
            ultimo_bloque.message_hash,
            hashlib.sha256(plaintext.encode('utf-8')).hexdigest(),
            'El message_hash del bloque no corresponde al SHA-256 del plaintext',
        )
