from django.urls import path
from . import views

urlpatterns = [
    path('',        views.get_chain,    name='blockchain-chain'),
    path('verify/', views.verify_chain, name='blockchain-verify'),
]
