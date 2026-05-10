from rest_framework import serializers


class SendMessageSerializer(serializers.Serializer):
    # Destino: exactamente uno
    recipient_id = serializers.UUIDField(required=False, allow_null=True)
    group_id = serializers.UUIDField(required=False, allow_null=True)

    # Plaintext: el servidor cifra; el cliente firma antes de enviar
    plaintext = serializers.CharField(required=True)

    # Firma ECDSA del SHA-256(plaintext), generada por el cliente antes de cifrar
    signature = serializers.CharField(required=True)

    def validate(self, data):
        has_recipient = bool(data.get('recipient_id'))
        has_group = bool(data.get('group_id'))

        if not has_recipient and not has_group:
            raise serializers.ValidationError("Either recipient_id or group_id is required.")
        if has_recipient and has_group:
            raise serializers.ValidationError("Provide either recipient_id or group_id, not both.")
        return data


class CreateGroupSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)
    member_ids = serializers.ListField(
        child=serializers.UUIDField(),
        min_length=1,
    )


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
