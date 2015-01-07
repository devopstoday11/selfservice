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

from pylons import request, response, tmpl_context as c
from pylons.controllers.util import abort, redirect
from pylons.templating import render_mako as render
from pylons.i18n.translation import get_lang

from linotpselfservice.lib.base import BaseController
from linotp.lib.reply import sendError

import json
import httplib
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

        log.debug("[__before__::%r] %r" % (action, params))

        try:

            self.context = self.get_preauth_context()
            c.secure_auth = self.context.get('secure_auth', False)
            c.version = self.context['version']
            c.licenseinfo = self.context['licenseinfo']
            c.browser_language = self.browser_language

        except httplib.HTTPException as httperr:
            log.error("[__before__::%r] httplib.HTTPException %r" %
                      (action, httperr))
            log.error("[__before__] %s" % traceback.format_exc())
            raise httperr

        except webob.exc.HTTPUnauthorized as acc:
            # # the exception, when an abort() is called if forwarded
            log.error("[__before__::%r] webob.exception %r" % (action, acc))
            log.error("[__before__] %s" % traceback.format_exc())
            raise acc

        except Exception as exx:
            log.error("[__before__::%r] exception %r" % (action, exx))
            log.error("[__before__] %s" % traceback.format_exc())
            if exx.strerror in ['Connection refused']:
                raise webob.exc.HTTPServiceUnavailable
            return sendError(response, exx, context='before')

        finally:
            log.debug("[__before__::%r] done" % (action))


    def login(self):
        log.debug("[login] selfservice login screen")
        identity = request.environ.get('repoze.who.identity')
        if identity is not None:
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

            response.status = '%i Logout from LinOTP selfservice' % LOGIN_CODE
            return render('/selfservice/login.mako')

        except Exception as exx:
            log.error('[login] failed %r' % exx)
            log.error('[login] %s' % traceback.format_exc())
            return self.sendError(response, exx)

        finally:
            pass


#eof##########################################################################

