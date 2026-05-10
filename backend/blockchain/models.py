import hashlib
import json
from django.db import models


class Block(models.Model):
    index         = models.IntegerField(unique=True)
    timestamp     = models.DateTimeField()
    sender_id     = models.UUIDField(null=True, blank=True)
    recipient_id  = models.UUIDField(null=True, blank=True)
    message_hash  = models.CharField(max_length=64)
    previous_hash = models.CharField(max_length=64)
    nonce         = models.IntegerField(default=0)
    hash          = models.CharField(max_length=64, unique=True)

    class Meta:
        db_table = 'blockchain'
        ordering = ['index']

    def __str__(self):
        return f"Block #{self.index} [{self.hash[:12]}…]"

    def compute_hash(self) -> str:
        """SHA-256(index | timestamp | sender_id | recipient_id | message_hash | previous_hash | nonce)"""
        payload = json.dumps({
            'index':         self.index,
            'timestamp':     self.timestamp.isoformat(),
            'sender_id':     str(self.sender_id) if self.sender_id else '',
            'recipient_id':  str(self.recipient_id) if self.recipient_id else '',
            'message_hash':  self.message_hash,
            'previous_hash': self.previous_hash,
            'nonce':         self.nonce,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()
