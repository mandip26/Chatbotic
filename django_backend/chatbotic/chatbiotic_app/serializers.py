from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
import re

class UserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'username', 'email', 'password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True},
            'username': {'read_only': True}
        }

    def validate_password(self, value):

        if len(value) < 8:
            raise serializers.ValidationError(
                "Password must be at least 8 characters long."
            )
        
        if len(value) > 128:
            raise serializers.ValidationError(
                "Password must not exceed 128 characters."
            )
        
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError(
                "Password must contain at least one uppercase letter."
            )
        
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError(
                "Password must contain at least one lowercase letter."
            )
        
        if not re.search(r'\d', value):
            raise serializers.ValidationError(
                "Password must contain at least one digit."
            )
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', value):
            raise serializers.ValidationError(
                "Password must contain at least one special character (!@#$%^&*()_+-=[]{}etc.)."
            )
        
        try:
            validate_password(value)
        except Exception as e:
            raise serializers.ValidationError(str(e))
        
        return value

    def validate(self, data):
        if data.get('password') != data.get('confirm_password'):
            raise serializers.ValidationError({
                'confirm_password': 'Passwords do not match.'
            })
        
        if not data.get('first_name'):
            raise serializers.ValidationError({
                'first_name': 'First name is required.'
            })
        
        if not data.get('email'):
            raise serializers.ValidationError({
                'email': 'Email is required.'
            })
        
        if User.objects.filter(email=data.get('email')).exists():
            raise serializers.ValidationError({
                'email': 'A user with this email already exists.'
            })
        
        password = data.get('password', '').lower()
        first_name = data.get('first_name', '').lower()
        if first_name and first_name in password:
            raise serializers.ValidationError({
                'password': 'Password should not contain your first name.'
            })
        
        last_name = data.get('last_name', '').lower()
        if last_name and last_name in password:
            raise serializers.ValidationError({
                'password': 'Password should not contain your last name.'
            })
        
        email = data.get('email', '').lower()
        if email:
            email_username = email.split('@')[0].lower()
            if email_username in password or email in password:
                raise serializers.ValidationError({
                    'password': 'Password cannot contain your email or email username.'
                })
        
        return data

    def create(self, validated_data):

        validated_data.pop('confirm_password', None)

        validated_data['username'] = validated_data['first_name']

        user = User.objects.create_user(**validated_data)
        
        return user