
try:
    import json
except ImportError:
    import simplejson as json



from paste.urlparser import PkgResourcesParser
from pylons.middleware import error_document_template
from webhelpers.html.builder import literal
from pylons import request, response, config, tmpl_context as c
from pylons.controllers.util import abort
from pylons.templating import render_mako as render

from linotpdselfservice.lib.util import check_selfservice_session
from linotpdselfservice.lib.base import BaseController
from linotp.lib.reply import sendError

from pylons.i18n.translation import _


import logging
log = logging.getLogger(__name__)

class UserserviceController(BaseController):
    """
    the Userservice controller is the proxy for the remote user selfservice
    interaction like the enabling/resetting++
    it directly interacts with the selfservice js controller and does not need
    a rendering context.
    """


    def __before__(self, action, **params):

            identity = request.environ.get('repoze.who.identity')
            if identity is None:
                abort(401, _("You are not authenticated"))

            log.debug("[__before__] doing getAuthFromIdentity in action %s" % action)

            if ';' in identity['repoze.who.userid']:
                self.userid, self.auth_cookie = identity['repoze.who.userid'].split(';', 1)
            else:
                self.userid = identity['repoze.who.userid']
                self.auth_cookie = None

            if action not in ['load_form']:
                if check_selfservice_session(request) == False:
                    abort(401, _("No valid session"))

    def enable(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/enable',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def disable(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/disable',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def delete(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/delete',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def reset(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/reset',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def unassigne(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/unassigne',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def setpin(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/setpin',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def setmpin(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/setmpin',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def resync(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/resync',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def assign(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/assign',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def unassign(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/unassign',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)


    def enroll(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/enroll',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def webprovision(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/webprovision',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def getmultiotp(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/getmultiotp',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def getSerialByOtp(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/getSerialByOtp',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def history(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/history',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def activateocratoken(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/activateocratoken',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def finshocra2token(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/finshocra2token',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def finshocratoken(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/finshocratoken',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

    def token_call(self):
        '''
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid
            reply = self.call_linotp('/userservice/token_call',
                                     params=params)
        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        response.content_type = 'application/json'
        return json.dumps(reply)

