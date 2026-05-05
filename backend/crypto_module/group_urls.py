from django.urls import path
from .views import CreateGroupView

urlpatterns = [
    path('', CreateGroupView.as_view(), name='create-group'),
]
