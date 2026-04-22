from django.urls import path
from .views import RegisterView, get_user_public_key

urlpatterns = [
    path('register', RegisterView.as_view(), name='auth-register'),
    path('users/<uuid:user_id>/key', get_user_public_key, name='get_user_public_key'),
]
