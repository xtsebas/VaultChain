import uuid
from django.db import models
from django.conf import settings


class Group(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'groups'

    def __str__(self):
        return self.name


class GroupMember(models.Model):
    group = models.ForeignKey(
        Group,
        on_delete=models.CASCADE,
        related_name='members',
        db_column='group_id',
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='group_memberships',
        db_column='user_id',
    )
    encrypted_key = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'group_members'
        unique_together = [('group', 'user')]

    def __str__(self):
        return f"GroupMember {self.user_id} in {self.group_id}"


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
    encrypted_key = models.TextField(blank=True, default='')
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
