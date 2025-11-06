from django.urls import path, include
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('user/register/', views.UserCreate.as_view(), name='user-register'),
    path('user/login/', views.LoginView.as_view(), name='user-login'),
    path('user/profile/', views.UserDetailView.as_view(), name='user-profile'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api-auth/', include('rest_framework.urls')),
    path('accounts/', include('allauth.urls')),
    path('callback/', views.google_login_callback, name='callback'),
    path('auth/user/', views.UserDetailView.as_view(), name='user_detail'),
    path('google/validate_token/', views.validate_google_token, name='validate_token'),
]