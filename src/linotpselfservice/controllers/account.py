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

"""
account controller - used for loggin in to the selfservice
"""


import traceback
import requests

from pylons import request, response, tmpl_context as c
from pylons.controllers.util import abort, redirect
from pylons.templating import render_mako as render
from pylons.i18n.translation import get_lang
from pylons.i18n.translation import _
from mako.exceptions import TopLevelLookupException

from linotpselfservice.lib.base import (BaseController,
                                        InvalidLinOTPResponse
                                        )

import json
import logging
import webob


log = logging.getLogger(__name__)

# The HTTP status code, that determines that
# the Login to the selfservice portal is required.
# Is also defined in selfservice.js
LOGIN_CODE = 576

class AccountController(BaseController):
    '''
    The AccountController
        /account/
    is responsible for authenticating the users for the selfservice portal.
    It has the following functions:
        /account/login
        /account/dologin
    '''


    def __before__(self, action, **params):
        """
        """
        log.debug("[__before__::%r] %r" % (action, params))

        try:
            c.otpLogin = False
            c.version = ''
            c.licenseinfo = ''
            c.browser_language = self.browser_language
            c.status = ''

            self.context = self.get_preauth_context()

            if not self.context:
                error = _("Failed to setup context - check your LinOTP connection!")
                raise Exception(error)

            c.otpLogin = self.context.get('otpLogin', False)
            c.version = self.context['version']
            c.licenseinfo = self.context['licenseinfo']
            c.browser_language = self.browser_language

        except InvalidLinOTPResponse as err:
            log.exception("[__before__::%r] InvalidLinOTPResponse %r",
                          action, err)
            c.code = err.reason
            c.error = (_("Invalid linotp response: %r") % err.url)
            c.status = ("%s: %s" % (err.reason, err.url))

            webException = webob.exc.HTTPServiceUnavailable()
            # templating for the connection error:
            # hard overwrite the default html content of the webob.exception
            # as described in documented in webob 8-/
            try:
                from string import Template
                body = render('/selfservice/error.mako')
                webException.html_template_obj = Template(body)
            except TopLevelLookupException as exx:
                log.error("Template lookup error %r", exx)

            raise webException

        except webob.exc.HTTPUnauthorized as acc:
            # the exception, when an abort() is called if forwarded
            log.error("[__before__::%r] webob.exception %r" % (action, acc))
            log.error("[__before__] %s" % traceback.format_exc())
            raise acc

        except requests.exceptions.RequestException as exx:
            # we create a customizable error document
            try:
                target_url = exx.message.url
            except AttributeError as exx:
                target_url = ''
            try:
                c.code = exx.message.reason.errno
            except AttributeError as exx:
                c.code = 567

            c.error = _("Failed to connect to the linotp server")
            try:
                c.status = ("%s: %s" %
                    (exx.message.reason.strerror, target_url))
            except AttributeError as exx:
                c.status = c.error

            webException = webob.exc.HTTPServiceUnavailable()
            # templating for the connection error:
            # hard overwrite the default html content of the webob.exception
            # as described in documented in webob 8-/
            try:
                from string import Template
                body = render('/selfservice/error.mako')
                webException.html_template_obj = Template(body)
            except TopLevelLookupException as exx:
                log.error("Template lookup error %r", exx)

            raise webException

        except Exception as exx:
            log.error("[__before__::%r] exception %r" % (action, exx))
            log.error("[__before__] %s" % traceback.format_exc())
            return self.sendError(response, exx, context='before')

        finally:
            log.debug("[__before__::%r] done" % (action))

    def login(self):
        """
        check for successfull authentication - or redirect to the login again
        """

        log.debug("[login] selfservice login screen")
        identity = request.environ.get('repoze.who.identity', None)

        # there is no way to get authentication failure information from
        # the repoze.who. Thus we have to use a hack here, by using the
        # identity with the prefix '::ERROR::'
        repoze_userid = None

        if identity and identity.get('repoze.who.userid', None):
            repoze_userid = identity['repoze.who.userid']

        if repoze_userid and "::ERROR::" in repoze_userid:
            status = repoze_userid

            # remove the error message identifier
            status = status.replace("::ERROR::", '')

            # as the repoze.who is not in the same scope of translation, we
            # submit the message to the login
            # transfered are two kind of errors, which are translated here
            # by using message replacement
            #::ERROR:: Authentication attempt failed!"
            #::ERROR:: Connection response '%r'"
            status = status.replace("Authentication attempt failed!",
                                    _("Authentication attempt failed!"))
            status = status.replace("Connection response:",
                                    _("Connection response:"))
            c.status = status
            repoze_userid = None
            identity = None

        if identity:
            # After login We always redirect to the start page
            redirect("/")

        res = {}
        try:
            if not self.context:
                raise Exception('Error: Connection error!')

            c.defaultRealm = self.context["default_realm"]

            c.realmArray = []
            c.realmbox = self.context["realm_box"]
            log.debug("[login] displaying realmbox: %i" % int(c.realmbox))
            if c.realmbox == True:
                realms = json.loads(self.context["realms"])
                for (k, v) in realms.items():
                    c.realmArray.append(k)

            status = _("Logout from LinOTP selfservice")
            response.status = '%i %s' % (LOGIN_CODE, status)
            return render('/selfservice/login.mako')

        except Exception as exx:
            log.error('[login] failed %r' % exx)
            log.error('[login] %s' % traceback.format_exc())
            return self.sendError(response, exx)

        finally:
            log.debug('finally')


#eof##########################################################################
