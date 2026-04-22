from rest_framework import serializers


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    display_name = serializers.CharField(max_length=100)
    password = serializers.CharField(min_length=8, write_only=True)
