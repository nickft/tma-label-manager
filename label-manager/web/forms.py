import datetime

from django import forms

from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _

class TrainingForm(forms.Form):
    number_of_videos = forms.IntegerField(help_text="Enter the number of videos.")
    session_duration = forms.IntegerField(help_text="Duration of captured video (in seconds)")
    bandwidth_limitations = forms.CharField(help_text="Comma-seperated text with the Mbps bandwidth limitations", required=False)

    def clean_number_of_videos(self):
        data = self.cleaned_data['number_of_videos']

        if data <= 0:
            raise ValidationError(_('Only positive numbers are accepted'))

        if data >= 1000:
            raise ValidationError(_('Are you crazy? This is gonna take years to finish'))

        # Remember to always return the cleaned data.
        return data

    def clean_bandwidth_limitations(self):
        data = self.cleaned_data['bandwidth_limitations']

        if(len(data) == 0): 
            return data

        commaNumber = data.count(',')
        elementList = data.split(',')
        elementNumber = len(elementList)

        # Check if a date is not in the past.
        if commaNumber < elementNumber - 1:
            raise ValidationError(_('Invalid input. Example: 0.25, 1, 1.2, 5'))

        for element in elementList:
            element = element.strip()
            try:
                float(element)
            except:
                raise ValidationError(_('Invalid input. Example: 0.25, 1, 1.2, 5'))

        # Remember to always return the cleaned data.
        return data

    def clean_session_duration(self):
        data = self.cleaned_data['session_duration']

        if data <= 0:
            raise ValidationError(_('Only positive numbers are accepted'))

        # Remember to always return the cleaned data.
        return data