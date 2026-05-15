"""
Tests — Encadenamiento de Bloques e Integridad de la Cadena.

Cubre:
  3. Encadenamiento correcto de hashes SHA-256 (criterio 5 de rúbrica)
  4. Genesis block y estructura (criterio 4 de rúbrica)
  5. Registro automático al enviar mensaje (criterio 7 de rúbrica)
  6. Endpoint GET /blockchain/verify/ — integridad completa (criterio 6 de rúbrica)
"""
import hashlib

from django.test import TestCase
from rest_framework import status
from rest_framework.test import APITestCase

from blockchain.chain import append_block
from blockchain.models import Block
from crypto_module.tests.helpers import make_access_token, make_crypto_user
from signatures.tests.helpers import make_ecdsa_user


VERIFY_URL   = '/blockchain/verify/'
MESSAGES_URL = '/messages/'


# ── 3. Encadenamiento correcto de bloques ────────────────────────────────────

class BlockChainingTest(TestCase):
    """
    Criterios 4 y 5: genesis block, estructura del bloque y encadenamiento
    correcto de hashes SHA-256.
    """

    def setUp(self):
        self.sender,    _ = make_crypto_user(email='bc_s@test.com', display_name='Sender')
        self.recipient, _ = make_crypto_user(email='bc_r@test.com', display_name='Recipient')

    def test_genesis_previous_hash_is_64_zeros(self):
        """El genesis block tiene previous_hash = '0' * 64 según la especificación."""
        genesis = Block.objects.get(index=0)
        self.assertEqual(genesis.previous_hash, '0' * 64)

    def test_genesis_hash_matches_compute_hash(self):
        """El hash almacenado del genesis coincide con compute_hash()."""
        genesis = Block.objects.get(index=0)
        self.assertEqual(genesis.hash, genesis.compute_hash())

    def test_first_block_links_to_genesis(self):
        """El primer bloque real tiene previous_hash igual al hash del genesis."""
        genesis = Block.objects.get(index=0)
        block = append_block(self.sender.id, self.recipient.id, 'Primer mensaje')
        self.assertEqual(block.previous_hash, genesis.hash)

    def test_block_stored_hash_matches_compute_hash(self):
        """El hash persistido en BD coincide con compute_hash() calculado en caliente."""
        block = append_block(self.sender.id, self.recipient.id, 'Verificación de hash')
        self.assertEqual(block.hash, block.compute_hash())

    def test_consecutive_blocks_chain_correctly(self):
        """previous_hash del bloque N+1 apunta exactamente al hash del bloque N."""
        b1 = append_block(self.sender.id, self.recipient.id, 'Bloque A')
        b2 = append_block(self.sender.id, self.recipient.id, 'Bloque B')
        self.assertEqual(b2.previous_hash, b1.hash)
        self.assertEqual(b2.index, b1.index + 1)

    def test_message_hash_is_sha256_of_plaintext(self):
        """message_hash almacenado es exactamente SHA-256(plaintext.encode('utf-8'))."""
        plaintext = 'Contenido auditable del mensaje'
        block = append_block(self.sender.id, self.recipient.id, plaintext)
        expected = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
        self.assertEqual(block.message_hash, expected)

    def test_three_consecutive_blocks_form_valid_chain(self):
        """Una cadena de 3 bloques mantiene los enlaces de previous_hash íntegros."""
        blocks = [
            append_block(self.sender.id, self.recipient.id, f'Mensaje {i}')
            for i in range(3)
        ]
        for i in range(1, len(blocks)):
            self.assertEqual(blocks[i].previous_hash, blocks[i - 1].hash)
            self.assertEqual(blocks[i].hash, blocks[i].compute_hash())


# ── 4. Verificación de integridad de la cadena completa ─────────────────────

class ChainIntegrityAPITest(APITestCase):
    """
    Criterio 6: Endpoint GET /blockchain/verify/ recorre toda la cadena
    y detecta inconsistencias en hashes o enlaces.
    """

    def setUp(self):
        self.alice, _ = make_ecdsa_user(email='ci_alice@test.com', display_name='Alice')
        self.bob,   _ = make_ecdsa_user(email='ci_bob@test.com',   display_name='Bob')
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {make_access_token(self.alice)}'
        )

    def _send(self, text='Mensaje de prueba'):
        self.client.post(MESSAGES_URL, {
            'recipient_id': str(self.bob.id),
            'plaintext':    text,
            'signature':    'fake-sig',
        }, format='json')

    def test_intact_chain_returns_valid_true(self):
        """Una cadena sin manipulaciones devuelve valid=True y HTTP 200."""
        self._send('Alpha')
        self._send('Beta')
        resp = self.client.get(VERIFY_URL)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertTrue(resp.json()['valid'])

    def test_verify_length_matches_db_count(self):
        """El campo length en la respuesta coincide con Block.objects.count()."""
        self._send('Conteo')
        data = self.client.get(VERIFY_URL).json()
        self.assertEqual(data['length'], Block.objects.count())

    def test_tampered_block_hash_detected(self):
        """
        Un bloque con hash adulterado directamente en BD provoca valid=False
        con reason='hash_mismatch' e indica el índice fallido.
        """
        self._send('Bloque a adulterar')
        victim = Block.objects.order_by('-index').first()
        Block.objects.filter(pk=victim.pk).update(hash='f' * 64)

        data = self.client.get(VERIFY_URL).json()
        self.assertFalse(data['valid'])
        self.assertEqual(data['reason'], 'hash_mismatch')
        self.assertEqual(data['failed_at_index'], victim.index)

    def test_broken_chain_link_detected(self):
        """
        Un bloque cuyo previous_hash no apunta al bloque anterior provoca
        valid=False con reason='broken_link'.
        El hash se recalcula para que no dispare hash_mismatch primero.
        """
        self._send('Enlace A')
        self._send('Enlace B')
        victim = Block.objects.order_by('-index').first()

        victim.previous_hash = 'e' * 64
        new_hash = victim.compute_hash()
        Block.objects.filter(pk=victim.pk).update(
            previous_hash='e' * 64,
            hash=new_hash,
        )

        data = self.client.get(VERIFY_URL).json()
        self.assertFalse(data['valid'])
        self.assertEqual(data['reason'], 'broken_link')
        self.assertEqual(data['failed_at_index'], victim.index)

    def test_chain_grows_and_stays_valid_after_messages(self):
        """
        Enviar mensajes incrementa la cadena y la verificación sigue retornando
        valid=True — confirma que el registro automático encadena correctamente.
        """
        before = Block.objects.count()
        for i in range(3):
            self._send(f'Mensaje {i}')

        data = self.client.get(VERIFY_URL).json()
        self.assertTrue(data['valid'])
        self.assertEqual(data['length'], before + 3)
