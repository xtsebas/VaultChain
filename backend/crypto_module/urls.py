from django.urls import path
from .views import SendMessageView, get_user_messages

urlpatterns = [
    path('', SendMessageView.as_view(), name='send-message'),
    path('<uuid:user_id>', get_user_messages, name='get-user-messages'),
]
