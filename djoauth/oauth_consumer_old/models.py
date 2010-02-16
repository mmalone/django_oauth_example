import urllib
from cgi import parse_qsl
from django.db import models
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse


class Service(models.Model):
    """Store the OAuth endpoint URLs for a Service."""
    name = models.CharField(max_length=256, unique=True)
    temporary_credentials_url = models.CharField(max_length=256)
    authorization_url = models.CharField(max_length=256)
    token_credentials_url = models.CharField(max_length=256)

    def get_absolute_url(self):
        return reverse('service', kwargs={'object_id': self.id})


class Token(models.Model):
    """
    An OAuth Token. Associated with a User.
    """
    TYPE_CLIENT = 0
    TYPE_TEMPORARY = 1
    TYPE_TOKEN = 2
    TYPE_CHOICES = (
        (TYPE_CLIENT, 'client'),
        (TYPE_TEMPORARY, 'temporary'),
        (TYPE_TOKEN, 'token'),
    )

    key = models.CharField(max_length=256, primary_key=True)
    secret = models.CharField(max_length=256)
    user = models.ForeignKey(User)
    service = models.ForeignKey(Service)
    type = models.IntegerField(choices=TYPE_CHOICES)

    callback = None
    callback_confirmed = None
    verifier = None

    def to_string(self):
        """Returns this token as a plain string."""
        data = {
            'oauth_token': self.key,
            'oauth_token_secret': self.secret,
        }
        if self.callback_confirmed:
            data['oauth_callback_confirmed'] = self.callback_confirmed
        return urllib.urlencode(data)

    @staticmethod
    def from_string(s):
        """Deserializes a token from a string like one returned by
        `to_string()`."""

        if not len(s):
            raise ValueError("Invalid parameter string.")

        params = dict(parse_qsl(s, keep_blank_values=False))
        if not params:
            raise ValueError("Invalid parameter string.")

        try:
            key = params['oauth_token']
        except KeyError:
            raise ValueError("'oauth_token' not found in OAuth request.")
        try:
            secret = params['oauth_token_secret']
        except KeyError:
            raise ValueError("'oauth_token_secret' not found in OAuth request.")

        token = Token(key, secret)
        try:
            token.callback_confirmed = params['oauth_callback_confirmed']
        except KeyError:
            pass # 1.0, no callback confirmed.
        return token

    def __str__(self):
        return self.to_string()
