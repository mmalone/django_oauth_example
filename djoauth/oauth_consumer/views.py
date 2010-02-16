import oauth2 as oauth
import urlparse
import urllib
import json
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse


CLIENT_KEY = 'your_twitter_key'
CLIENT_SECRET = 'your_twitter_secret'


TEMP_CREDENTIALS_KEY = '__temp_credentials__'
TOKEN_CREDENTIALS_KEY = '__token_credentials__'


def consumer(request):
    """Connects an account to a service."""
    consumer = oauth.Consumer(CLIENT_KEY, CLIENT_SECRET)
    credentials = request.session.get(TOKEN_CREDENTIALS_KEY, None)
    if credentials is None:
        client = oauth.Client(consumer)
        url = 'https://twitter.com/oauth/request_token?%s' % (urllib.urlencode({
            'oauth_callback': request.build_absolute_uri(reverse('callback')),
        }))
        resp, content = client.request(url, 'GET')
        if resp['status'] != '200':
            raise Exception('Invalid response: %s.' % (resp['status'],))
        temporary_credentials = dict(urlparse.parse_qsl(content))
        request.session[TEMP_CREDENTIALS_KEY] = temporary_credentials
        auth_url = 'https://twitter.com/oauth/authorize?%s' % (urllib.urlencode({
            'oauth_token': temporary_credentials['oauth_token'],
        }))
        return HttpResponseRedirect(auth_url)
    else:
        try:
            credentials = oauth.Token(credentials['oauth_token'],
                                      credentials['oauth_token_secret'])
            client = oauth.Client(consumer, credentials)
            resp, content = client.request('http://twitter.com/account/verify_credentials.json', 'GET')
            data = json.loads(content)
            return HttpResponse('Logged in as %s' % (data['screen_name'],))
        except:
            del request.session[TOKEN_CREDENTIALS_KEY]
            raise


def callback(request):
    temp_credentials = request.session.get(TEMP_CREDENTIALS_KEY, None)
    if temp_credentials is None:
        raise Exception('No temporary credentials.')
    temp_credentials = oauth.Token(temp_credentials['oauth_token'],
                                   temp_credentials['oauth_token_secret'])
    consumer = oauth.Consumer(CLIENT_KEY, CLIENT_SECRET)
    client = oauth.Client(consumer, temp_credentials)
    url = 'https://twitter.com/oauth/access_token?%s' % (urllib.urlencode({
        'oauth_verifier': request.GET.get('oauth_verifier', '')
    }))
    resp, content = client.request(url, 'POST')
    access_token = dict(urlparse.parse_qsl(content))
    request.session[TOKEN_CREDENTIALS_KEY] = access_token
    return HttpResponseRedirect(reverse('consumer'))
