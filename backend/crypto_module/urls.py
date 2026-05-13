from django.urls import path
from .views import SendMessageView, get_user_messages, verify_message

urlpatterns = [
    path('', SendMessageView.as_view(), name='send-message'),
    path('<uuid:msg_id>/verify', verify_message, name='verify-message'),
    path('<uuid:user_id>', get_user_messages, name='get-user-messages'),
]
