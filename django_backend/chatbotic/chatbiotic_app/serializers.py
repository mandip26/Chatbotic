from django.contrib.auth.models import User
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True, required=True)
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'username', 'email', 'password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True},
            'username': {'read_only': True}
        }

    def validate(self, data):
        if data.get('password') != data.get('confirm_password'):
            raise serializers.ValidationError({
                'confirm_password': 'Passwords do not match.'
            })
        
        if not data.get('first_name'):
            raise serializers.ValidationError({
                'first_name': 'First name is required.'
            })
        
        return data

    def create(self, validated_data):

        validated_data.pop('confirm_password', None)

        validated_data['username'] = validated_data['first_name']

        user = User.objects.create_user(**validated_data)
        return user