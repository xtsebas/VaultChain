"""
Tests E2E — Encadenamiento de bloques y registro automático (Fase 3).

Cubre:
  1. Genesis block creado por migración
  2. compute_hash() produce el mismo hash que el almacenado en el genesis
  3. append_block() encadena correctamente (previous_hash == hash del bloque anterior)
  4. message_hash = SHA-256(plaintext)
  5. Enviar un mensaje directo crea un nuevo bloque automáticamente
  6. Enviar dos mensajes produce cadena de 3 bloques (genesis + 2) con hashes íntegros
  7. Enviar un mensaje grupal registra un bloque en el blockchain
  8. Concurrencia: append_block() no genera índices duplicados
  9. GET /blockchain/ retorna la cadena completa con estructura correcta
 10. GET /blockchain/verify/ valida la cadena íntegra
 11. GET /blockchain/verify/ detecta hash adulterado y enlace roto
"""
import hashlib
import threading
from unittest import skipIf

from django.conf import settings
from django.test import TestCase, TransactionTestCase
from rest_framework.test import APITestCase
from rest_framework import status

from blockchain.models import Block
from blockchain.chain import append_block, compute_message_hash
from crypto_module.tests.helpers import make_crypto_user, make_access_token
from crypto_module.models import Group, GroupMember


MESSAGES_URL    = '/messages/'
GROUPS_URL      = '/groups/'
BLOCKCHAIN_URL  = '/blockchain/'
VERIFY_URL      = '/blockchain/verify/'


# ── Utilidades ────────────────────────────────────────────────────────────────

def _chain_is_valid():
    """Recorre la cadena verificando que cada bloque apunte al anterior."""
    blocks = list(Block.objects.order_by('index'))
    for i in range(1, len(blocks)):
        if blocks[i].previous_hash != blocks[i - 1].hash:
            return False
        if blocks[i].hash != blocks[i].compute_hash():
            return False
    return True


# ── 1. Genesis block ──────────────────────────────────────────────────────────

class GenesisBlockTest(TestCase):
    def test_genesis_block_exists(self):
        self.assertTrue(Block.objects.filter(index=0).exists())

    def test_genesis_previous_hash_is_64_zeros(self):
        genesis = Block.objects.get(index=0)
        self.assertEqual(genesis.previous_hash, '0' * 64)

    def test_genesis_hash_matches_compute_hash(self):
        genesis = Block.objects.get(index=0)
        self.assertEqual(genesis.hash, genesis.compute_hash())

    def test_genesis_message_hash_is_64_zeros(self):
        genesis = Block.objects.get(index=0)
        self.assertEqual(genesis.message_hash, '0' * 64)


# ── 2. compute_hash y message_hash ───────────────────────────────────────────

class HashComputationTest(TestCase):
    def test_compute_message_hash_is_sha256_of_plaintext(self):
        plaintext = 'Mensaje de prueba VaultChain'
        expected  = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
        self.assertEqual(compute_message_hash(plaintext), expected)

    def test_compute_hash_is_deterministic(self):
        genesis = Block.objects.get(index=0)
        self.assertEqual(genesis.compute_hash(), genesis.compute_hash())

    def test_hash_changes_if_content_changes(self):
        genesis = Block.objects.get(index=0)
        original_hash = genesis.compute_hash()
        genesis.nonce = 1
        self.assertNotEqual(genesis.compute_hash(), original_hash)


# ── 3. append_block — encadenamiento ─────────────────────────────────────────

class AppendBlockTest(TestCase):
    def setUp(self):
        self.sender,    _ = make_crypto_user(email='s@test.com', display_name='Sender')
        self.recipient, _ = make_crypto_user(email='r@test.com', display_name='Recipient')

    def test_append_creates_block_with_index_1(self):
        block = append_block(self.sender.id, self.recipient.id, 'Hola mundo')
        self.assertEqual(block.index, 1)

    def test_appended_block_previous_hash_equals_genesis_hash(self):
        genesis = Block.objects.get(index=0)
        block   = append_block(self.sender.id, self.recipient.id, 'Hola')
        self.assertEqual(block.previous_hash, genesis.hash)

    def test_appended_block_hash_is_correct(self):
        block = append_block(self.sender.id, self.recipient.id, 'Hola')
        self.assertEqual(block.hash, block.compute_hash())

    def test_message_hash_in_block_is_sha256_of_plaintext(self):
        plaintext = 'Mensaje secreto'
        block = append_block(self.sender.id, self.recipient.id, plaintext)
        expected = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
        self.assertEqual(block.message_hash, expected)

    def test_two_appends_produce_valid_chain(self):
        b1 = append_block(self.sender.id, self.recipient.id, 'Primer mensaje')
        b2 = append_block(self.sender.id, self.recipient.id, 'Segundo mensaje')

        self.assertEqual(b2.index, b1.index + 1)
        self.assertEqual(b2.previous_hash, b1.hash)
        self.assertTrue(_chain_is_valid())

    def test_sender_and_recipient_ids_stored(self):
        block = append_block(self.sender.id, self.recipient.id, 'Test')
        self.assertEqual(str(block.sender_id),    str(self.sender.id))
        self.assertEqual(str(block.recipient_id), str(self.recipient.id))

    def test_group_message_block_has_null_recipient(self):
        block = append_block(self.sender.id, None, 'Mensaje grupal')
        self.assertIsNone(block.recipient_id)


# ── 4. Registro automático al enviar mensaje directo ─────────────────────────

class DirectMessageBlockchainTest(APITestCase):
    def setUp(self):
        self.sender,    _ = make_crypto_user(email='alice@test.com', display_name='Alice')
        self.recipient, _ = make_crypto_user(email='bob@test.com',   display_name='Bob')
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.sender)}'
        )

    def test_sending_message_creates_one_block(self):
        count_before = Block.objects.count()

        self.client.post(MESSAGES_URL, {
            'recipient_id': str(self.recipient.id),
            'plaintext':    'Mensaje de prueba',
            'signature':    'fake-sig',
        }, format='json')

        self.assertEqual(Block.objects.count(), count_before + 1)

    def test_block_links_correctly_to_previous(self):
        last_before = Block.objects.order_by('-index').first()

        self.client.post(MESSAGES_URL, {
            'recipient_id': str(self.recipient.id),
            'plaintext':    'Hola Bob',
            'signature':    'fake-sig',
        }, format='json')

        new_block = Block.objects.order_by('-index').first()
        self.assertEqual(new_block.previous_hash, last_before.hash)

    def test_message_hash_in_block_matches_plaintext(self):
        plaintext = 'Contenido verificable'

        self.client.post(MESSAGES_URL, {
            'recipient_id': str(self.recipient.id),
            'plaintext':    plaintext,
            'signature':    'fake-sig',
        }, format='json')

        new_block = Block.objects.order_by('-index').first()
        expected  = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
        self.assertEqual(new_block.message_hash, expected)

    def test_two_messages_produce_valid_chain(self):
        for i in range(2):
            self.client.post(MESSAGES_URL, {
                'recipient_id': str(self.recipient.id),
                'plaintext':    f'Mensaje {i}',
                'signature':    'fake-sig',
            }, format='json')

        self.assertTrue(_chain_is_valid())

    def test_chain_integrity_after_three_messages(self):
        for i in range(3):
            resp = self.client.post(MESSAGES_URL, {
                'recipient_id': str(self.recipient.id),
                'plaintext':    f'Mensaje numero {i}',
                'signature':    'fake-sig',
            }, format='json')
            self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        blocks = list(Block.objects.order_by('index'))
        # genesis + 3 mensajes = 4 bloques
        self.assertEqual(len(blocks), 4)
        self.assertTrue(_chain_is_valid())


# ── 5. Registro automático en mensaje grupal ──────────────────────────────────

class GroupMessageBlockchainTest(APITestCase):
    def setUp(self):
        self.sender,    _ = make_crypto_user(email='owner@test.com', display_name='Owner')
        self.member,    _ = make_crypto_user(email='member@test.com', display_name='Member')
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.sender)}'
        )
        # Crear grupo con ambos como miembros
        resp = self.client.post(GROUPS_URL, {
            'name': 'Grupo Test',
            'member_ids': [str(self.sender.id), str(self.member.id)],
        }, format='json')
        self.group_id = resp.json()['id']

    def test_group_message_creates_one_block(self):
        count_before = Block.objects.count()

        self.client.post(MESSAGES_URL, {
            'group_id':  self.group_id,
            'plaintext': 'Hola grupo',
            'signature': 'fake-sig',
        }, format='json')

        self.assertEqual(Block.objects.count(), count_before + 1)

    def test_group_block_has_null_recipient(self):
        self.client.post(MESSAGES_URL, {
            'group_id':  self.group_id,
            'plaintext': 'Mensaje grupal',
            'signature': 'fake-sig',
        }, format='json')

        new_block = Block.objects.order_by('-index').first()
        self.assertIsNone(new_block.recipient_id)
        self.assertEqual(str(new_block.sender_id), str(self.sender.id))


# ── 6. Concurrencia — sin índices duplicados ──────────────────────────────────

@skipIf(
    settings.DATABASES['default']['ENGINE'] == 'django.db.backends.sqlite3',
    'SQLite usa bloqueo a nivel de archivo; select_for_update() requiere PostgreSQL para este test.'
)
class ConcurrentAppendTest(TransactionTestCase):
    """
    TransactionTestCase porque select_for_update() requiere transacciones reales
    (TestCase envuelve todo en un savepoint que no permite el bloqueo a nivel fila).
    Solo se ejecuta en PostgreSQL — SQLite no soporta bloqueo a nivel de fila.
    """
    def setUp(self):
        import importlib
        migration = importlib.import_module('blockchain.migrations.0002_genesis_block')
        # TransactionTestCase flushes data but keeps the schema, so the table already exists.
        # Only insert the genesis block; no need to recreate the table.
        migration.insert_genesis_block(
            type('Apps', (), {'get_model': staticmethod(lambda a, m: Block)}), None
        )

    def test_concurrent_appends_produce_unique_indexes(self):
        sender,    _ = make_crypto_user(email='c_s@test.com', display_name='CS')
        recipient, _ = make_crypto_user(email='c_r@test.com', display_name='CR')

        errors  = []
        threads = []

        def do_append():
            try:
                append_block(sender.id, recipient.id, 'concurrent')
            except Exception as e:
                errors.append(str(e))

        for _ in range(5):
            t = threading.Thread(target=do_append)
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f'Errors during concurrent appends: {errors}')
        indexes = list(Block.objects.exclude(index=0).values_list('index', flat=True))
        self.assertEqual(len(indexes), len(set(indexes)), 'Duplicate indexes found')


# ── 7. GET /blockchain/ ───────────────────────────────────────────────────────

class GetChainAPITest(APITestCase):
    """
    Flujo real: dos usuarios se envían mensajes → se consulta GET /blockchain/
    y se verifica que la respuesta refleja exactamente el estado de la BD.
    """
    def setUp(self):
        self.alice, _ = make_crypto_user(email='gc_alice@test.com', display_name='Alice')
        self.bob,   _ = make_crypto_user(email='gc_bob@test.com',   display_name='Bob')
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.alice)}'
        )

    def test_chain_endpoint_returns_200(self):
        resp = self.client.get(BLOCKCHAIN_URL)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_chain_includes_genesis_block(self):
        resp = self.client.get(BLOCKCHAIN_URL)
        data = resp.json()
        self.assertIn('chain', data)
        genesis = data['chain'][0]
        self.assertEqual(genesis['index'], 0)
        self.assertEqual(genesis['previous_hash'], '0' * 64)

    def test_chain_length_grows_after_messages(self):
        before = self.client.get(BLOCKCHAIN_URL).json()['length']

        for i in range(3):
            self.client.post(MESSAGES_URL, {
                'recipient_id': str(self.bob.id),
                'plaintext':    f'Hola Bob número {i}',
                'signature':    'fake-sig',
            }, format='json')

        after = self.client.get(BLOCKCHAIN_URL).json()['length']
        self.assertEqual(after, before + 3)

    def test_chain_block_structure_has_required_fields(self):
        self.client.post(MESSAGES_URL, {
            'recipient_id': str(self.bob.id),
            'plaintext':    'Mensaje de estructura',
            'signature':    'fake-sig',
        }, format='json')

        data  = self.client.get(BLOCKCHAIN_URL).json()
        block = data['chain'][-1]  # el bloque recién creado

        for field in ('index', 'timestamp', 'sender_id', 'recipient_id',
                      'message_hash', 'previous_hash', 'nonce', 'hash'):
            self.assertIn(field, block, f'Campo "{field}" ausente en el bloque')

    def test_chain_blocks_are_ordered_by_index(self):
        for i in range(2):
            self.client.post(MESSAGES_URL, {
                'recipient_id': str(self.bob.id),
                'plaintext':    f'Orden {i}',
                'signature':    'fake-sig',
            }, format='json')

        chain = self.client.get(BLOCKCHAIN_URL).json()['chain']
        indexes = [b['index'] for b in chain]
        self.assertEqual(indexes, sorted(indexes))

    def test_chain_length_matches_db_count(self):
        self.client.post(MESSAGES_URL, {
            'recipient_id': str(self.bob.id),
            'plaintext':    'Conteo',
            'signature':    'fake-sig',
        }, format='json')

        data = self.client.get(BLOCKCHAIN_URL).json()
        self.assertEqual(data['length'], Block.objects.count())


# ── 8. GET /blockchain/verify/ ────────────────────────────────────────────────

class VerifyChainAPITest(APITestCase):
    """
    Flujo real en tres escenarios:
      A) Cadena íntegra tras enviar mensajes  → valid=True
      B) Bloque con hash adulterado           → valid=False, reason=hash_mismatch
      C) Bloque con previous_hash roto        → valid=False, reason=broken_link
    """
    def setUp(self):
        self.alice, _ = make_crypto_user(email='vc_alice@test.com', display_name='Alice')
        self.bob,   _ = make_crypto_user(email='vc_bob@test.com',   display_name='Bob')
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.alice)}'
        )

    def _send(self, text):
        self.client.post(MESSAGES_URL, {
            'recipient_id': str(self.bob.id),
            'plaintext':    text,
            'signature':    'fake-sig',
        }, format='json')

    # ── A: cadena íntegra ────────────────────────────────────────────────────

    def test_verify_returns_200(self):
        resp = self.client.get(VERIFY_URL)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_verify_intact_chain_is_valid(self):
        self._send('Primero')
        self._send('Segundo')
        self._send('Tercero')

        data = self.client.get(VERIFY_URL).json()
        self.assertTrue(data['valid'])
        self.assertEqual(data['length'], Block.objects.count())

    # ── B: hash adulterado ───────────────────────────────────────────────────

    def test_verify_detects_tampered_hash(self):
        self._send('Mensaje antes de adulteración')
        victim = Block.objects.order_by('-index').first()

        # Adulteramos el hash almacenado directamente en BD
        Block.objects.filter(pk=victim.pk).update(hash='a' * 64)

        data = self.client.get(VERIFY_URL).json()
        self.assertFalse(data['valid'])
        self.assertEqual(data['reason'], 'hash_mismatch')
        self.assertEqual(data['failed_at_index'], victim.index)

    # ── C: enlace roto (previous_hash incorrecto) ────────────────────────────

    def test_verify_detects_broken_link(self):
        self._send('Bloque A')
        self._send('Bloque B')
        victim = Block.objects.order_by('-index').first()

        # Rompemos el enlace pero mantenemos el hash internamente consistente:
        # previous_hash apunta a un bloque inexistente, y recalculamos hash
        # con ese nuevo previous_hash para que hash_mismatch NO se dispare.
        victim.previous_hash = 'b' * 64
        new_hash = victim.compute_hash()
        Block.objects.filter(pk=victim.pk).update(
            previous_hash='b' * 64,
            hash=new_hash,
        )

        data = self.client.get(VERIFY_URL).json()
        self.assertFalse(data['valid'])
        self.assertEqual(data['reason'], 'broken_link')
        self.assertEqual(data['failed_at_index'], victim.index)
