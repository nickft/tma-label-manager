from os import name
from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('createTraining', views.createTraining, name='create-training'),
    path('requestVideo', views.requestVideo, name='request-video'),
    path('startVideo/<video_id>', views.startVideo, name='start-video'),
    path('finishVideo/<video_id>', views.finishVideo, name='finish-video'),
    path('enforceBandwith/<video_id>', views.enforceBandwith, name='enforce-bandwith'),
    path('download/<training_id>', views.downloadDataset, name='download-dataset'),
    path('stopTraining/<training_id>', views.stopTraining, name='stop-training'),
    path('deleteTraining/<training_id>', views.deleteTraining, name='delete-training')
]
