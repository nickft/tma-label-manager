from django.shortcuts import render

from django import forms
from django.utils import timezone
from django.conf import settings
from django.http import HttpResponseRedirect
from django.http import JsonResponse

from .models import *
from .forms import *

import os
import random
import requests


def index(request):

    training_list = Training.objects.all()

    training = next(filter(lambda t: not t.has_finished, training_list), None)

    form = TrainingForm()

    context = {
        'form': form,
        'training': training
    }

    return render(request, 'web/index.html', context)


def requestVideo(request):
    
    training_list = Training.objects.all()

    training = next(filter(lambda t: not t.has_finished, training_list), None)

    session_list = Session.objects.filter(training=training)

    selectedSession = None

    for session in session_list:
        if session.status == -1:
            selectedSession = session
            break

    responseData={}

    #If there is extra video to capture,
    if(selectedSession):
        responseData['finished'] = False
        responseData['video_id'] = selectedSession.id
        responseData['video_url'] = selectedSession.url
        responseData['banwidth_limitation'] = selectedSession.bw_limitation
    else:
        responseData['finished'] = True
        training.has_finished = True
        training.save()
        
    return JsonResponse(responseData)


def createTraining(request):
    
    form = TrainingForm(request.POST or None)

    # Check if the form is valid:
    if form.is_valid():
        # process the data in form.cleaned_data as required (here we just write it to the model due_back field)

        training = Training()
        training.name = "Dataset Collection"
        training.created_at = timezone.now()
        training.number_of_videos = form.cleaned_data['number_of_videos']
        training.bw_limitations = form.cleaned_data['bandwidth_limitations']
        training.session_duration = form.cleaned_data['session_duration']
        training.has_finished = False

        training.save()

        # To avoid it create a list of real twitch channel names
        channel_name_list = getChannelNameList(100)

        for i in range(0, training.number_of_videos):

            channel_name = random.choice(channel_name_list)

            session = Session()
            session.name = "Session {}".format(i)
            session.training = training
            session.url = "https://player.twitch.tv/?channel={}".format(channel_name) 
            session.status = -1
            if training.bw_limitations: 
                bandwidth_limitation_list = training.bw_limitations.split(",")
                number_of_bandwidth_limitations = len(bandwidth_limitation_list)

                bandwidth_limitation_index = i% number_of_bandwidth_limitations

                session.bw_limitation = float(bandwidth_limitation_list[bandwidth_limitation_index].strip())
            else:
                session.bw_limitation = -1

            session.save()

        return HttpResponseRedirect("/")     

    context = {
        'form': form,
    }

    return render(request, 'web/index.html', context)


def requestTwitchToken():
    session = requests.Session()

    response = session.post("https://id.twitch.tv/oauth2/token?client_id="+settings.TWITCH_CLIENT_ID+"&client_secret="+settings.TWITCH_CLIENT_SECRET+"&grant_type=client_credentials")
    
    response.raise_for_status()

    access_token = response.json()['access_token']

    return access_token

def getChannelNameList(number_of_streams = 20):

    access_token = requestTwitchToken()

    session = requests.Session() 
    session.headers.update({'Authorization': 'Bearer '+access_token, 'Client-Id': settings.TWITCH_CLIENT_ID})
    response = session.get("https://api.twitch.tv/helix/streams?first="+str(number_of_streams))

    response.raise_for_status()

    channel_name_list = []

    for channel in response.json()['data']:
        channel_name_list.append(channel['user_login'])

    return channel_name_list

