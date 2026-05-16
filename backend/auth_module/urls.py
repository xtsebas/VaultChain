from django.urls import path
from .views import (
    RegisterView, LoginView, MFAEnableView, MFAVerifyView,
    RefreshTokenView, get_user_public_key, list_users,
)

urlpatterns = [
    path('register', RegisterView.as_view(), name='auth-register'),
    path('login', LoginView.as_view(), name='auth-login'),
    path('token/refresh', RefreshTokenView.as_view(), name='auth-token-refresh'),
    path('mfa/enable', MFAEnableView.as_view(), name='auth-mfa-enable'),
    path('mfa/verify', MFAVerifyView.as_view(), name='auth-mfa-verify'),
    path('users/', list_users, name='list-users'),
    path('users/<uuid:user_id>/key', get_user_public_key, name='get_user_public_key'),
]
