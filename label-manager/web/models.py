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

class TrainingSession(models.Model):
    name = models.TextField()
    training = models.ForeignKey(Training, on_delete=CASCADE)
    created_at = models.DateTimeField(blank=True, null=True)
    finished_at = models.DateTimeField(blank=True, null=True)
    url = models.TextField()
    status = models.IntegerField()
    bw_limitation = models.FloatField()

    def __str__(self):
        return self.name