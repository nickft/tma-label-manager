from django.db import models
from django.db.models.deletion import CASCADE

# Create your models here.
class Training(models.Model):
    name = models.TextField()
    created_at = models.DateTimeField()
    finished_at = models.DateTimeField(blank=True, null=True)
    number_of_videos = models.IntegerField()
    bw_limitations = models.TextField()
    session_duration = models.FloatField()
    has_finished = models.BooleanField()
    
    def __str__(self):
        return self.name

class Session(models.Model):
    name = models.TextField()
    training = models.ForeignKey(Training, on_delete=CASCADE)
    created_at = models.DateTimeField(blank=True, null=True)
    finished_at = models.DateTimeField(blank=True, null=True)
    url = models.TextField()
    status = models.IntegerField() # -1 For not captured yet. 0 For under capturing. 1 For captured video
    bw_limitation = models.FloatField()
    application_data = models.TextField(blank=True, null=True)
    network_data = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name