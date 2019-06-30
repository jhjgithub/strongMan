# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import messages
from django.shortcuts import render
from django_tables2 import RequestConfig

from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import HttpResponse
from django.template import RequestContext, loader

from .vpninfo import OverviewHandler

#from strongMan.apps.pools.models import Pool
#from strongMan.helper_apps.vici.wrapper.exception import ViciException
#from .. import tables
#from strongMan.helper_apps.vici.wrapper.wrapper import ViciWrapper

# Create your views here.


#class OverviewHandler(object):
#    def __init__(self, request):
#        self.request = request
#        self.ENTRIES_PER_PAGE = 50
#
#    def handle(self):
#        pass
#        try:
#            return self._render()
#        #except ViciException as e:
#        except Exception as e:
#            messages.warning(self.request, str(e))
#
#    def _render(self):
#        return render(self.request, 'server_tunnels/tunnels.html', {'message': "This is messages !!!!"})
#        #response = "You're looking at the results of question."
#        #return HttpResponse(response)


@require_http_methods('GET')
@login_required
def overview(request):
    handler = OverviewHandler(request)
    #handler = TunnelListHandler(request)
    return handler.handle()
    #template = loader.get_template('server_tunnels/tunnels.html')
    #context = RequestContext(request, {'message': 'This is messages !!!!!'})
    #return HttpResponse(template.render(context))


def _get_title(form):
    return form.get_choice_name()


def _get_type_name(cls):
    return type(cls).__name__
