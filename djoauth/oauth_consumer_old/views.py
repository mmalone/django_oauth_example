import oauth2 as oauth
import urlparse
import urllib
from djoauth.oauth_consumer import models, forms
from django.contrib.auth.decorators import login_required
from django.template import RequestContext
from django.shortcuts import render_to_response, get_object_or_404
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse


TEMP_CREDENTIALS_KEY = '__temp_credentials__'
SERVICE_KEY = '__service_key__'


def parameterize_url(url, params):
    """ 
    Adds query string parameters to a URL that may already contain a query string.
    """
    url = list(urlparse.urlparse(url))
    params = urllib.urlencode(params)
    if url[4]:
        url[4] = '%s&%s' % (url[4], params)
    else:
        url[4] = params
    return urlparse.urlunparse(url)


@login_required
def connect_account(request, service_id=None):
    """Connects an account to a service."""
    if service_id is None:
        return render_to_response('oauth_consumer/services.html', {
            'services': models.Service.objects.all(),
        }, RequestContext(request))
    else:
        service = get_object_or_404(models.Service, id=service_id)
        try:
            client_token = models.Token.objects.get(user=request.user, service=service, type=models.Token.TYPE_CLIENT)
        except models.Token.DoesNotExist:
            return HttpResponseRedirect(reverse('client_credentials', kwargs={'service_id': service.id}))
        consumer = oauth.Consumer(client_token.key, client_token.secret)
        client = oauth.Client(consumer)
        temp_credentials_url = parameterize_url(service.temporary_credentials_url, {
            'oauth_callback': 'http://localhost:8000/callback/',
        })
        resp, content = client.request(temp_credentials_url, 'GET')
        if resp['status'] != '200':
            raise Exception('Invalid response: %s.' % (resp['status'],))
        temporary_credentials = dict(urlparse.parse_qsl(content))
        request.session[TEMP_CREDENTIALS_KEY] = temporary_credentials
        request.session[SERVICE_KEY] = service_id
        authorization_url = parameterize_url(service.authorization_url, {
            'oauth_token': temporary_credentials['oauth_token'],
        })
        return HttpResponseRedirect(authorization_url)


@login_required
def callback(request):
    temp_credentials = request.session.get(TEMP_CREDENTIALS_KEY, None)
    if temp_credentials is None:
        raise Exception('No temporary credentials.')
    temp_credentials = oauth.Token(temp_credentials['oauth_token'],
                                   temp_credentials['oauth_token_secret'])
    service_id = request.session[SERVICE_KEY]
    service = get_object_or_404(models.Service, kwargs={'pk': service_id})
    client_token = get_object_or_404(models.Token, kwargs={
        'user': request.user,
        'service': service,
        'type': models.Token.TYPE_CLIENT
    })
    consumer = oauth.Consumer(client_token.key, client_token.secret)
    client = oauth.Client(consumer, temp_credentials)
    resp, content = client.request(


@login_required
def client_credentials(request, service_id):
    service = get_object_or_404(models.Service, id=service_id)
    form = forms.TokenForm(request.POST)
    if form.is_valid():
        token = models.Token(form.cleaned_data['key'], form.cleaned_data['secret'])
        token.user = request.user
        token.service = service
        token.type = models.Token.TYPE_CLIENT
        token.save()
        return HttpResponseRedirect(reverse('connect_account', kwargs={'service_id': service.id}))
    return render_to_response('oauth_consumer/client_credentials.html', {
        'form': form,
    }, RequestContext(request))
