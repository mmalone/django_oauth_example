from django.conf.urls.defaults import *

urlpatterns = patterns('',
    url('^$', 'djoauth.oauth_consumer.views.consumer', name='consumer'),
    url('^callback/$', 'djoauth.oauth_consumer.views.callback', name='callback'),
)
