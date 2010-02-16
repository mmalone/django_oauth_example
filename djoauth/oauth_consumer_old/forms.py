from django.forms import ModelForm
from djoauth.oauth_consumer import models

class TokenForm(ModelForm):
    class Meta:
        model = models.Token
        exclude = ('type', 'service', 'user')
