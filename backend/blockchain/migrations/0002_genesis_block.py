import hashlib
import json
from datetime import datetime, timezone

from django.db import migrations


GENESIS_TIMESTAMP = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
GENESIS_PREVIOUS_HASH = '0' * 64


def _compute_hash(index, timestamp, sender_id, recipient_id, message_hash, previous_hash, nonce):
    payload = json.dumps({
        'index':         index,
        'timestamp':     timestamp.isoformat(),
        'sender_id':     sender_id,
        'recipient_id':  recipient_id,
        'message_hash':  message_hash,
        'previous_hash': previous_hash,
        'nonce':         nonce,
    }, sort_keys=True)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def insert_genesis_block(apps, schema_editor):
    Block = apps.get_model('blockchain', 'Block')

    if Block.objects.filter(index=0).exists():
        return

    genesis_hash = _compute_hash(
        index=0,
        timestamp=GENESIS_TIMESTAMP,
        sender_id='',
        recipient_id='',
        message_hash='0' * 64,
        previous_hash=GENESIS_PREVIOUS_HASH,
        nonce=0,
    )

    Block.objects.create(
        index=0,
        timestamp=GENESIS_TIMESTAMP,
        sender_id=None,
        recipient_id=None,
        message_hash='0' * 64,
        previous_hash=GENESIS_PREVIOUS_HASH,
        nonce=0,
        hash=genesis_hash,
    )


def remove_genesis_block(apps, schema_editor):
    Block = apps.get_model('blockchain', 'Block')
    Block.objects.filter(index=0).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('blockchain', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(insert_genesis_block, remove_genesis_block),
    ]
