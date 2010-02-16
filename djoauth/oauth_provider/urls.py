from django.conf.urls.defaults import *

urlpatterns = patterns('',
    url('^temporary_credentials/$', 'djoauth.oauth_provider.views.temporary_credentials', name='temporary_credentials'),
    url('^authorize/$', 'djoauth.oauth_provider.views.authorize', name='authorize'),
    url('^token_credentials/$', 'djoauth.oauth_provider.views.token_credentials', name='token_credentials'),
    url('^protected_resource/$', 'djoauth.oauth_provider.views.protected_resource', name='protected_resource'),
)
