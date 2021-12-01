from django.shortcuts import render
from django.http import JsonResponse

def index(request):
    context = None
    return render(request, 'web/index.html', context)

def predict(request):

    responseData={}

    if request.method =='POST':
        # TODO pickle.load() models and predict the result

        # TODO construct response based on the results of each model

        responseData["status"] = "Pending..."
    else:
        responseData["status"] = "Error. Request is invalid."
    return JsonResponse(responseData)