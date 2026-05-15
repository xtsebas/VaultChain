"""
chain.py — Lógica de encadenamiento del mini-blockchain de VaultChain.

Fórmula oficial del spec:
  hash_actual = SHA-256(index + timestamp + datos + previous_hash + nonce)

"datos" = sender_id + recipient_id + message_hash
donde message_hash = SHA-256(plaintext original del mensaje).
"""
import hashlib
import logging

from django.db import transaction
from django.utils import timezone

from .models import Block

logger = logging.getLogger(__name__)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def compute_message_hash(plaintext: str) -> str:
    """SHA-256 del plaintext. Es el 'dato de la transacción' que va al bloque."""
    return _sha256(plaintext)


def append_block(sender_id, recipient_id, plaintext: str) -> Block:
    """
    Crea y persiste el siguiente bloque en la cadena.

    Usa select_for_update() para serializar escrituras concurrentes y
    garantizar que no se produzcan dos bloques con el mismo index.

    Raises:
        Exception — si la escritura en BD falla. El caller decide si
                    propagar o silenciar el error.
    """
    message_hash = compute_message_hash(plaintext)

    with transaction.atomic():
        # Bloquea el último bloque para evitar race conditions
        last_block = (
            Block.objects
            .select_for_update()
            .order_by('-index')
            .first()
        )

        if last_block is None:
            raise RuntimeError(
                'Blockchain vacío: el genesis block no existe. '
                'Ejecuta las migraciones antes de enviar mensajes.'
            )

        new_index     = last_block.index + 1
        previous_hash = last_block.hash
        timestamp     = timezone.now()

        block = Block(
            index=new_index,
            timestamp=timestamp,
            sender_id=sender_id,
            recipient_id=recipient_id,
            message_hash=message_hash,
            previous_hash=previous_hash,
            nonce=0,
        )
        block.hash = block.compute_hash()
        block.save()

    logger.info(
        'Block #%d appended | hash=%s | prev=%s',
        block.index, block.hash[:16], previous_hash[:16],
    )
    return block
