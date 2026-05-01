import uuid
from django.db import models
from django.conf import settings


class Message(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='sent_messages',
        db_column='sender_id',
    )
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='received_messages',
        db_column='recipient_id',
    )
    group_id = models.UUIDField(null=True, blank=True)
    ciphertext = models.TextField()
    encrypted_key = models.TextField()
    nonce = models.CharField(max_length=24)
    auth_tag = models.CharField(max_length=24)
    signature = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'messages'
        indexes = [
            models.Index(fields=['sender'], name='idx_messages_sender'),
            models.Index(fields=['recipient'], name='idx_messages_recipient'),
        ]

    def __str__(self):
        return f"Message {self.id} from {self.sender_id}"
