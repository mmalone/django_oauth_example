from django.conf.urls.defaults import *

urlpatterns = patterns('',
    (r'^consumer/', include('djoauth.oauth_consumer.urls')),
    (r'^provider/', include('djoauth.oauth_provider.urls')),
    url(r'^login/', 'django.contrib.auth.views.login', name='login'),
    url(r'^logout/', 'django.contrib.auth.views.logout', name='logout'),
)
