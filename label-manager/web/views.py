from django.shortcuts import render

from django import forms
from django.utils import timezone
from django.conf import settings
from django.http import HttpResponseRedirect, StreamingHttpResponse
from django.http import JsonResponse

from .models import *
from .forms import *
from .network import *

import os
import random
import requests
import json
import threading

def index(request):

    form = TrainingForm()

    unfinished_training_list = Training.objects.filter(has_finished=False)

    training=None

    if(not len(unfinished_training_list) == 0):
        training = unfinished_training_list[0]

        if Session.objects.filter(training=training, status=0): 
            session = Session.objects.get(training=training, status=0)
            session.status = -1
            session.save()

    finished_training_list = Training.objects.filter(has_finished=True)

    context = {
        'form': form,
        'training': training,
        'finished_training_list': finished_training_list
    }

    return render(request, 'web/index.html', context)

def deleteTraining(request, training_id):
    training = Training.objects.get(id=training_id)
    training.delete()
    
    return JsonResponse({"status": 'ok'})

def stopTraining(request, training_id):
    training = Training.objects.get(id=training_id)

    unfinished_session_list = Session.objects.filter(training=training).exclude(status=1)

    training.number_of_videos = training.number_of_videos - len(unfinished_session_list)

    unfinished_session_list.delete()

    training.has_finished = True
    training.finished_at = timezone.now()

    training.save()

    return HttpResponseRedirect("/")

def downloadDataset(request, training_id):
    training = Training.objects.get(id=training_id)

    file_name = "dataset-"+str(training.id)+".csv"
    file_url = "/code/datasets/"+file_name

    # Collect info only from the successfully captured datasets
    session_list = Session.objects.filter(training=training, status=1)

    with open(file_url, 'w+') as fw:

        network_data_dict = json.loads(session_list[0].network_data)
        application_data_dict = json.loads(session_list[0].application_data)

        columnList=["id", "bw", "duration"]

        columnList.extend(network_data_dict.keys())
        columnList.extend(application_data_dict.keys())

        fw.write(','.join([str(i) for i in columnList]) + "\n")

        for session in session_list:

            network_data_dict = json.loads(session.network_data)
            application_data_dict = json.loads(session.application_data)
            
            columnList=[session.id, session.bw_limitation, training.session_duration]
            columnList.extend(network_data_dict.values())
            columnList.extend(application_data_dict.values())

            fw.write(','.join([str(i) for i in columnList]) + "\n")

    def file_iterator(file, chunk_size=512):
        with open(file, 'rb') as f:
            while True:
                c = f.read(chunk_size)
                if c:
                    yield c
                else:
                    break
        os.remove(file)

    response = StreamingHttpResponse(file_iterator(file_url))
    response['Content-Type'] = 'application/octet-stream'
    response['Content-Disposition'] = 'attachment;filename="{0}"'.format(file_name)
    return response

def startVideo(request, video_id):

    session = Session.objects.get(id=video_id)

    # Start capturing traffic using a thread function
    thread = threading.Thread(target=captureTraffic, args=(settings.CAPTURE_INTERFACE, session))
    thread.start()

    responseData={}
    if(session.status == -1):
        responseData['video_id'] = session.id
        responseData['video_url'] = session.url
        responseData['duration'] = session.training.session_duration
        responseData['bandwidth_limitation'] = session.bw_limitation
        responseData['order'] = Session.objects.filter(training = session.training).exclude(status=-1).count()+1
        responseData['discarded'] = session.training.discarded_sessions
        responseData['total_videos'] = session.training.number_of_videos
    elif(session.status == 0):
        responseData['errorMessage'] = "The video is under capturing. What are you doing??"
    else:
        responseData['errorMessage'] = "The video has already been captured. How did you get there? "

    # Update the status of the session to "Under Capturing"
    session.status = 0
    session.started_at = timezone.now()
    session.save()

    return JsonResponse(responseData)

def finishVideo(request, video_id):

    if request.method == 'POST':
        session = Session.objects.get(id=video_id)

        # Retrieve network data based on tstat result
        input_network_data = getTstatStatistics(session)

        if(input_network_data is None):
            session.status = -1
            session.save()

            training = session.training
            training.discarded_sessions = training.discarded_sessions + 1
            training.save()
        else:
            # Retrieve application data from 
            input_application_data = request.POST.get('application_data')

            # Update the status of the session to "Finished Capturing"
            session.status = 1
            session.finished_at = timezone.now()
            session.network_data = input_network_data
            session.application_data = input_application_data
            session.save()

        #Send an empty response
        responseData={}

    return JsonResponse(responseData)    

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

        channel_name = getAChannelName()
        print("Found a new channel to connect {}".format(channel_name))
        selectedSession.url = channel_name
        selectedSession.save()

        responseData['finished'] = False
        responseData['video_id'] = selectedSession.id
        responseData['video_url'] = channel_name
    else:
        responseData['finished'] = True
        number_of_collected_sessions = Session.objects.filter(training=training, status=1).count()
        
        if(number_of_collected_sessions != training.number_of_videos):
            print("{} sessions were discarded".format(training.number_of_videos - number_of_collected_sessions))
        
        training.finished_at = timezone.now()
        training.has_finished = True
        training.save()
        
    return JsonResponse(responseData)

def enforceBandwith(request, video_id):

    session = Session.objects.get(id=video_id)
    
    enforceNetworkLimitation(settings.CAPTURE_INTERFACE, session)
    responseData={}

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
        training.discarded_sessions = False

        training.save()

        # To avoid it create a list of real twitch channel names
        channel_name_list = getChannelNameList(100)

        for i in range(0, training.number_of_videos):

            session = Session()
            session.name = "Session {}".format(i)
            session.training = training
            session.url = "Default. It will be initialized when video starts"
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

    #print(response.json())

    response.raise_for_status()

    channel_name_list = []

    for channel in response.json()['data']:
        # Ignore channels that require user intervention to accept the "is mature" pop-up message
        if channel['is_mature']:
            continue
            
        channel_name_list.append(channel['user_login'])

    return channel_name_list

def getAChannelName():

    access_token = requestTwitchToken()

    session = requests.Session() 
    session.headers.update({'Authorization': 'Bearer '+access_token, 'Client-Id': settings.TWITCH_CLIENT_ID})
    response = session.get("https://api.twitch.tv/helix/streams?first="+str(20))

    response.raise_for_status()

    channel_name_list = []

    for channel in response.json()['data']:
        # Ignore channels that require user intervention to accept the "is mature" pop-up message
        if channel['is_mature']:
            continue
            
        channel_name_list.append(channel['user_login'])

    return random.choice(channel_name_list)


