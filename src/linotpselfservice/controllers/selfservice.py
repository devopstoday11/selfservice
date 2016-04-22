# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

try:
    import json
except ImportError:
    import simplejson as json

from pylons import request, response, config, tmpl_context as c
from pylons.controllers.util import abort
from pylons.templating import render_mako as render

from linotpselfservice.lib.util import check_selfservice_session
from linotpselfservice.lib.base import BaseController

from pylons.i18n.translation import _


import logging
log = logging.getLogger(__name__)

def copy_context_(context):
    """
    copy the retrieved context to the global rendering context
    !sideeffect: changes the global rendering context c

    :param context:  retrieved context

    """
    for k, v in context.items():
        if k == 'user':
            user = v
            if '@' in user:
                user, realm = user.split('@')
                c.user = user
                c.realm = realm
            else:
                c.user = v
        else:
            setattr(c, k, v)

    return

class SelfserviceController(BaseController):
    """
    the selfservice controller is the one that
    - triggers the rendering of the selfservice components (mako's)
    - and provides the context information, which is required for the
      rendering
    """


    def __before__(self, action, **params):

        c.browser_language = self.browser_language

        identity = request.environ.get('repoze.who.identity')
        if identity is None:
            response.delete_cookie('userauthcookie')
            abort(401, _("You are not authenticated"))

        log.debug("getAuthFromIdentity in action %s" % action)
        if ';' in identity['repoze.who.userid']:
            self.userid, self.auth_cookie = identity['repoze.who.userid'].split(';', 1)
        else:
            self.userid = identity['repoze.who.userid']
            self.auth_cookie = None
        try:
            self.context = self.get_context({"user" :self.userid})
        except Exception as exx:
            log.error("linotp context lookup failed %r" % exx)
            response.delete_cookie('userauthcookie')
            abort(401, _("You are not authenticated"))

        copy_context_(self.context)

        # we need not to check the session here as here only the
        # rendering data is retreived which is sometimes static and
        # without session context (load_form). The real session check
        # is made at userservice within action callback

    def index(self):
        '''
        This is the redirect to the first template
        '''
        c.title = _("LinOTP Self Service")
        ren = render('/selfservice/base.mako')
        return ren

    def load_form(self):
        '''
        retrieve the form data eg. for token enrollment

        the load_form rendering context is rebuild on the LinOTP server side
        from the provided user context
        '''
        params = {}
        reply = {}
        try:
            params.update(request.params)
            params['user'] = self.userid

            reply = self.call_linotp('/userservice/load_form',
                                     params=params, return_json=False)

        except Exception as exx:
            log.error("failed to call remote service: %r" % exx)
            self.sendError(response, "%r" % exx)

        # the reply shoud be of type html
        return reply

    def custom_style(self):
        '''
        In case the user hasn't defined a custom css, Pylons calls this action.
        Return an empty file instead of a 404 (which would mean hitting the
        debug console)
        '''
        response.headers['Content-type'] = 'text/css'
        return ''

    def assign(self):
        '''
        In this form the user may assign an already existing Token to himself.
        For this, the user needs to know the serial number of the Token.
        '''
        return render('/selfservice/assign.mako')

    def resync(self):
        '''
        In this form, the user can resync an HMAC based OTP token
        by providing two OTP values
        '''
        return render('/selfservice/resync.mako')

    def reset(self):
        '''
        In this form the user can reset the Failcounter of the Token.
        '''
        return render('/selfservice/reset.mako')

    def getotp(self):
        '''
        In this form, the user can retrieve OTP values
        '''
        return render('/selfservice/getotp.mako')

    def disable(self):
        '''
        In this form the user may select a token of his own and
        disable this token.
        '''
        return render('/selfservice/disable.mako')

    def enable(self):
        '''
        In this form the user may select a token of his own and
        enable this token.
        '''
        return render('/selfservice/enable.mako')

    def unassign(self):
        '''
        In this form the user may select a token of his own and
        unassign this token.
        '''
        return render('/selfservice/unassign.mako')

    def delete(self):
        '''
        In this form the user may select a token of his own and
        delete this token.
        '''
        return render('/selfservice/delete.mako')


    def setpin(self):
        '''
        In this form the user may set the OTP PIN, which is the static password
        he enters when logging in in front of the otp value.
        '''
        return render('/selfservice/setpin.mako')

    def setmpin(self):
        '''
        In this form the user my set the PIN for his mOTP application soft
        token on his phone. This is the pin, he needs to enter on his phone,
        before a otp value will be generated.
        '''
        return render('/selfservice/setmpin.mako')

    def history(self):
        '''
        This is the form to display the history table for the user
        '''
        return render('/selfservice/history.mako')

    def webprovisionoathtoken(self):
        '''
        This is the form for an oathtoken to do web provisioning.
        '''
        return render('/selfservice/webprovisionoath.mako')

    def webprovisiongoogletoken(self):
        '''
        This is the form for an google token to do web provisioning.
        '''
        # c.actions = getSelfserviceActions(self.authUser)
        return render('/selfservice/webprovisiongoogle.mako')

    def usertokenlist(self):
        '''
        return the html for the tokenlist
        '''
        return render('/selfservice/tokenlist.mako')

    def activateqrtoken(self):
        '''
        return the form for an qr token activation
        '''
        return render('/selfservice/activateqr.mako')
