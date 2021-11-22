from os import name
from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('createTraining', views.createTraining, name='create-training'),
]
