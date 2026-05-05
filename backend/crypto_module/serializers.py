from rest_framework import serializers


class SendMessageSerializer(serializers.Serializer):
    recipient_id = serializers.UUIDField(required=True)
    plaintext = serializers.CharField(required=True)


class MessageResponseSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    sender_id = serializers.UUIDField()
    recipient_id = serializers.UUIDField()
    ciphertext = serializers.CharField()
    encrypted_key = serializers.CharField()
    nonce = serializers.CharField()
    auth_tag = serializers.CharField()
    signature = serializers.CharField(allow_null=True)
    created_at = serializers.DateTimeField()
