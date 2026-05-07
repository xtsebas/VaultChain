from django.urls import path
from .views import CreateGroupView, GetGroupMessagesView

urlpatterns = [
    path('', CreateGroupView.as_view(), name='create-group'),
    path('<uuid:group_id>/messages', GetGroupMessagesView.as_view(), name='get-group-messages'),
]
