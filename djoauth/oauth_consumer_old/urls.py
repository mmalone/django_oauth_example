from django.conf.urls.defaults import *
from djoauth.oauth_consumer import models

urlpatterns = patterns('',
    url('service/$', 'django.views.generic.create_update.create_object', {'model': models.Service}, name='create_service'),
    url('service/(?P<object_id>\d+)/$', 'django.views.generic.create_update.update_object', {'model': models.Service}, name='service'),
    url('connect_account/$', 'djoauth.oauth_consumer.views.connect_account', name='connect_account'),
    url('connect_account/(?P<service_id>\d+)/$', 'djoauth.oauth_consumer.views.connect_account', name='connect_account'),
    url('client_credentials/(?P<service_id>\d+)/$', 'djoauth.oauth_consumer.views.client_credentials', name='client_credentials'),
)
