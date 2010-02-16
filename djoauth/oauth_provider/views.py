import oauth2 as oauth
import urllib
import urlparse
from djoauth.oauth_provider import models
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response
from django.template import RequestContext


class HttpResponseUnauthorized(HttpResponse):
    status_code = 401


INVALID_PARAMS_RESPONSE = HttpResponseUnauthorized(content='Missing OAuth request parameters.')


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


def oauth_request(token_required=True, token_type=models.Token.TYPE_TOKEN):
    def _wrapped(real_view):
        def _view(request, *args, **kwargs):
            headers = request.META.copy()
            if headers.get('HTTP_AUTHORIZATION'):
                headers['Authorization'] = headers.pop('HTTP_AUTHORIZATION')
            # Only include POST data in signature if the content type is
            # application/x-www-form-urlencoded.
            content_type = request.META.get('CONTENT_TYPE', '').split(';')[0]
            if content_type == 'application/x-www-form-urlencoded':
                parameters = request.REQUEST.items()
            else:
                parameters = request.GET.items()
            oauth_request = oauth.Request.from_request(
                request.method,
                request.build_absolute_uri(),
                headers=headers,
                parameters=dict(parameters),
                query_string=request.environ.get('QUERY_STRING', '')
            )
            if not oauth_request:
                return INVALID_PARAMS_RESPONSE
            try:
                consumer = models.Consumer.objects.get(pk=oauth_request['oauth_consumer_key'])
            except (KeyError, models.Consumer.DoesNotExist):
                raise HttpUnauthorized('Consumer key missing or invalid.')
            server = oauth.Server()
            server.add_signature_method(oauth.SignatureMethod_HMAC_SHA1())             
            if token_required:
                try:
                    token = models.Token.objects.get(pk=oauth_request['oauth_token'], type=token_type)
                except (KeyError, models.Token.DoesNotExist):
                    return HttpResponseUnauthorized('Token missing or invalid.')
                oauth_token = oauth.Token(token.key, token.secret)
            else:
                token, oauth_token = None, None
            try:
                oauth_consumer = oauth.Consumer(consumer.key, consumer.secret)
                server.verify_request(oauth_request, oauth_consumer, oauth_token)
            except ValueError, ex:
                return HttpResponseUnauthorized(str(ex))
            request.oauth_request = oauth_request
            request.consumer = consumer
            request.token = token
            request.user = token.user if token is not None else None
            return real_view(request, *args, **kwargs)
        return _view
    return _wrapped


@oauth_request(token_required=False)
def temporary_credentials(request):
    """
    The Consumer obtains unauthorized temporary credentials by asking the server
    to issue a credentials. The client must then redirect the user to the server
    to authorize the temporary credentials, at which point they can be exchanged
    for token credentials.
    """
    token = models.Token(consumer=request.consumer, type=models.Token.TYPE_TEMPORARY)
    try:
        token.callback = request.oauth_request['oauth_callback']
    except KeyError:
        return HttpResponse('Missing oauth_callback', status=400)
    token.consumer = request.consumer
    token.save()
    data = {
        'oauth_token': token.key,
        'oauth_token_secret': token.secret,
        'oauth_callback_confirmed': True,
    }
    return HttpResponse(urllib.urlencode(data))


@login_required
def authorize(request):
    try:
        token = models.Token.objects.get(pk=request.GET['oauth_token'])
    except (KeyError, models.Token.DoesNotExist):
        raise Http404()
    if not token.type == token.TYPE_TEMPORARY:
        raise Http404()
    if request.method == 'GET':
        return render_to_response('authorize.html', {
            'consumer': token.consumer,
        }, RequestContext(request))
    elif request.method == 'POST':
        token.approved = True
        token.user = request.user
        token.verifier = models.make_random_key()
        token.save()
        callback = parameterize_url(token.callback, {
            'oauth_token': token.key,
            'oauth_verifier': token.verifier,
        })
        return HttpResponseRedirect(callback)
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])


@oauth_request(token_type=models.Token.TYPE_TEMPORARY)
def token_credentials(request):
    """
    After authorization, the Consumer exchanges their temporary credentials for
    token credentials, which can be used to access protected resources.
    """
    if not request.token.approved:
        return HttpResponseUnauthorized('Temporary token not authorized.')
    if request.token.verifier != request.oauth_request.get('oauth_verifier', None):
        return HttpResponseUnauthorized('Missing or invalid OAuth verifier.')
    token = models.Token(
        consumer=request.consumer, 
        type=models.Token.TYPE_TOKEN,
        user=request.token.user,
        approved=True
    )
    token.save()
    data = {
        'oauth_token': token.key,
        'oauth_token_secret': token.secret,
    }
    request.token.delete() # temporary tokens can only be redeemed once.
    return HttpResponse(urllib.urlencode(data))


@oauth_request()
def protected_resource(request):
    if request.user is None:
        raise HttpResponseUnauthorized()
    return HttpResponse(request.user.username)
