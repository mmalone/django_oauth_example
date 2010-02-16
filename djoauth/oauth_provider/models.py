from django.db import models
from random import choice
from django.contrib.auth.models import User
from itertools import izip


KEY_SIZE = 32


def make_random_key(length=KEY_SIZE, allowed_chars='abcdefghjklmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'):
    "Generate a random key with the given length and allowed_chars."
    return ''.join(choice(allowed_chars) for _ in xrange(length))


class Consumer(models.Model):
    def __init__(self, *args, **kwargs):
        key =  None
        secret = None
        # look for key, secret in args and kwargs, else generate random ones
        for val, field in izip(args, self._meta.fields):
            if field.attname == 'key':
                key = val 
            if field.attname == 'secret':
                secret = val 
        if not key and 'key' not in kwargs:
            kwargs['key'] = make_random_key()
        if not secret and 'secret' not in kwargs:
            kwargs['secret'] = make_random_key()
        return super(Consumer, self).__init__(*args, **kwargs)

    name = models.CharField(max_length=255)
    key = models.CharField(max_length=KEY_SIZE, primary_key=True)
    secret = models.CharField(max_length=KEY_SIZE)


class Token(models.Model):
    """
    An OAuth Token. Associated with a User.
    """
    TYPE_TEMPORARY = 0
    TYPE_TOKEN = 1
    TYPE_CHOICES = (
        (TYPE_TEMPORARY, 'temporary'),
        (TYPE_TOKEN, 'token'),
    )

    def __init__(self, *args, **kwargs):
        key =  None
        secret = None
        # look for key, secret in args and kwargs, else generate random ones
        for val, field in izip(args, self._meta.fields):
            if field.attname == 'key':
                key = val 
            if field.attname == 'secret':
                secret = val 
        if not key and 'key' not in kwargs:
            kwargs['key'] = make_random_key()
        if not secret and 'secret' not in kwargs:
            kwargs['secret'] = make_random_key()
        return super(Token, self).__init__(*args, **kwargs)

    key = models.CharField(max_length=256, primary_key=True)
    secret = models.CharField(max_length=256)
    verifier = models.CharField(max_length=256)
    type = models.IntegerField(choices=TYPE_CHOICES)
    callback = models.CharField(max_length=2048, blank=True)
    consumer = models.ForeignKey(Consumer)
    user = models.ForeignKey(User, blank=True, null=True)
    approved = models.BooleanField(default=False)
