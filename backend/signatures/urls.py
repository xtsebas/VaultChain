from django.urls import path
from . import views

urlpatterns = [
    path('verify/', views.verify_message_signature, name='verify-signature'),
]
