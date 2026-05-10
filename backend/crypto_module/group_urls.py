from django.urls import path
from .views import CreateGroupView, get_group

urlpatterns = [
    path('', CreateGroupView.as_view(), name='create-group'),
    path('<uuid:group_id>', get_group, name='get-group'),
]
