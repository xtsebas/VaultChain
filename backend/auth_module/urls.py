from django.urls import path
from . import views

urlpatterns = [
    path('users/<uuid:user_id>/key', views.get_user_public_key, name='get_user_public_key'),
]
