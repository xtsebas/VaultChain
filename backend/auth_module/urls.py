from django.urls import path
from .views import RegisterView, LoginView, get_user_public_key

urlpatterns = [
    path('register', RegisterView.as_view(), name='auth-register'),
    path('login', LoginView.as_view(), name='auth-login'),
    path('users/<uuid:user_id>/key', get_user_public_key, name='get_user_public_key'),
]
