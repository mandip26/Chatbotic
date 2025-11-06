from django.shortcuts import redirect
from django.contrib.auth.models import User
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserSerializer, LoginSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from allauth.socialaccount.models import SocialToken, SocialAccount
from django.contrib.auth.decorators import login_required
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

# Create your views here.
User = get_user_model()

class UserCreate(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
    
class LoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            return Response({
                'message': 'Login successful',
                'access_token': serializer.validated_data['access_token'],
                'refresh_token': serializer.validated_data['refresh_token'],
                'user': serializer.get_user(serializer.validated_data)
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@login_required
def google_login_callback(request):
    user = request.user

    social_account = SocialAccount.objects.filter(user=user)
    print("Social Account:", social_account)

    social_account = social_account.first() 
    if not social_account:
        print("No social account found.", user)
        return JsonResponse({'error': 'No social account found'}, status=400)
    
    token = SocialToken.objects.filter(account=social_account, account__providers='google').first()

    if token:
        print("Google Token:", token.token)
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        return JsonResponse({'access_token': access_token})
    else:
        print("No token found for the social account.", user)
        return JsonResponse({'error': 'No token found'}, status=400)
    
@csrf_exempt
def validate_google_token(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            google_access_token = data.get('access_token')
            print(google_access_token)

            if not google_access_token:
                return JsonResponse({'detail': 'Access token is missing'}, status=400)
            return JsonResponse({'valid': True})
        except json.JSONDecodeError:
            return JsonResponse({'detail': 'Invalid JSON'}, status=400)
    return JsonResponse({'detail': 'Method not allowed'}, status=405)