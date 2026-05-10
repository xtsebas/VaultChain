from rest_framework import serializers


class EncryptedKeyItemSerializer(serializers.Serializer):
    user_id = serializers.UUIDField()
    encrypted_key = serializers.CharField()


class SendMessageSerializer(serializers.Serializer):
    # Destino: exactamente uno
    recipient_id = serializers.UUIDField(required=False, allow_null=True)
    group_id = serializers.UUIDField(required=False, allow_null=True)

    # Payload cifrado (el cliente hace el cifrado)
    ciphertext = serializers.CharField(required=True)
    nonce = serializers.CharField(required=True)
    auth_tag = serializers.CharField(required=True)

    # Mensaje directo: una sola clave cifrada
    encrypted_key = serializers.CharField(required=False, default='')

    # Mensaje grupal: clave cifrada por miembro
    encrypted_keys = serializers.ListField(
        child=EncryptedKeyItemSerializer(),
        required=False,
        default=list,
    )

    def validate(self, data):
        has_recipient = bool(data.get('recipient_id'))
        has_group = bool(data.get('group_id'))

        if not has_recipient and not has_group:
            raise serializers.ValidationError("Either recipient_id or group_id is required.")
        if has_recipient and has_group:
            raise serializers.ValidationError("Provide either recipient_id or group_id, not both.")
        if has_recipient and not data.get('encrypted_key'):
            raise serializers.ValidationError("encrypted_key is required for direct messages.")
        if has_group and not data.get('encrypted_keys'):
            raise serializers.ValidationError("encrypted_keys is required for group messages.")
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
