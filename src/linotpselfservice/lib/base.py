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

"""The base Controller API

Provides the BaseController class for subclassing.
"""

from pylons import request, response, tmpl_context as c

from pylons.controllers import WSGIController
from pylons.i18n.translation import set_lang
from pylons.i18n import LanguageError

from linotpselfservice.config.environment import app_config
from linotpselfservice.lib.util import get_version
from linotpselfservice.lib.network import Connection

import json
import re
import os

import traceback
import logging


log = logging.getLogger(__name__)

# HTTP-ACCEPT-LANGUAGE strings are in the form of i.e.
# de-DE, de; q=0.7, en; q=0.3
accept_language_regexp = re.compile(r'\s*([^\s;,]+)\s*[;\s*q=[0-9.]*]?\s*,?')


class InvalidLinOTPResponse(Exception):
    """
    Exception raised, when an invalid response is returned by LinOTP
    """
    def __init__(self, error, url='', path='', status_code=None, reason=None):
        self.url = url
        self.path = path
        self.status_code = status_code
        self.reason = reason

        super(InvalidLinOTPResponse, self).__init__(self)

class BaseController(WSGIController):

    def __call__(self, environ, start_response):
        """Invoke the Controller"""
        # WSGIController.__call__ dispatches to the Controller method
        # the request is routed to. This routing information is
        # available in environ['pylons.routes_dict']

        return WSGIController.__call__(self, environ, start_response)


    def __init__(self, *args, **kw):

        self.context = {}

        self.conn = None
        self.request = request
        self.response = response
        self.set_language(request.headers)

        self.parent = super(WSGIController, self)
        self.parent.__init__(*args, **kw)

        self.config = app_config['app_conf']
        self.here = app_config['here']
        self.browser_language = request.headers.get('Accept-Language', None)

        try:
            self.base_url = self.config['linotp_url']
            #trim trailing slashes
            while self.base_url[-1] == '/':
                self.base_url = self.base_url[:-1]
        except KeyError:
            raise Exception("Missing definition of remote linotp url"
                            " in application ini: linotp_url")

        # load keyfile
        client_key = self.config.get('client_key', None)
        self.client_key = None
        # replace the app root %here% if any
        if client_key and '%(here)s' in client_key:
            client_key = client_key.replace('%(here)s', self.here)

        if client_key:
            if os.path.exists(client_key):
                self.client_key = client_key
            else:
                log.error("key_file %s could not be found", client_key)

        # load the client certificate file
        client_cert = self.config.get('client_cert', None)
        self.client_cert = None
        # replace the app root %here% if any
        if client_cert and '%(here)s' in client_cert:
            client_cert = client_cert.replace('%(here)s', self.here)

        if client_cert:
            if os.path.exists(client_cert):
                self.client_cert = client_cert
            else:
                log.error("cert_file %s could not be found", client_cert)

        # load the server certificate file
        server_cert = self.config.get('server_cert', None)
        self.server_cert = None
        # replace the app root %here% if any
        if server_cert and '%(here)s' in server_cert:
            server_cert = server_cert.replace('%(here)s', self.here)

        if server_cert:
            if os.path.exists(server_cert):
                self.server_cert = server_cert
            else:
                log.error("cert_file %s could not be found", server_cert)

        self.remote_base = self.config.get('linotp_remote_base', '/userservice')

        return

    def call_linotp(self, url, params=None, return_json=True):
        """
        make a http request to the linotp server

        :param url: the path of the linotp resource
        :param params: dict with request parameters
        :param return_json: bool, response should already be a json loaded obj

        :return: return the response of the request as dict or as plain text

        """
        if not self.conn:
            self.conn = Connection(
                self.base_url,
                server_cert=self.server_cert,
                client_cert=self.client_cert,
                client_key=self.client_key
                )

        if params is None:
            params = {}

        headers = {"Content-type": "application/x-www-form-urlencoded",
                   "Accept": "text/plain",
                   }

        # for locale support, we copy the incomming languege settings
        if self.browser_language:
            headers['Accept-Language'] = self.browser_language

        if not self.conn.is_user_session_set:
            # if we are requesting for a user, provide the user auth cookie
            if 'user' in params:
                if hasattr(self, 'auth_cookie') and self.auth_cookie:
                    self.conn.set_user_session(self.auth_cookie, params['user'])

        path = url

        if 'session' in params:
            # If a session is contained in params it is the local selfservice
            # session (between the browser and this server) not the session
            # between selfservice and LinOTP. Therefore we delete it. The
            # selfservice->LinOTP session has already been set with
            # 'self.conn.set_user_session'
            del params['session']

        net_response = self.conn.post(path, params=params, headers=headers)

        if net_response.status_code != 200:
            error = "%s%s: %s - %s" % (self.config.get('linotp_url', ''), path,
                                       net_response.status_code,
                                       net_response.reason)
            log.error(error)

            raise InvalidLinOTPResponse(error,
                                        url=self.config.get('linotp_url', ''),
                                        path=path,
                                        status_code=net_response.status_code,
                                        reason=net_response.reason)

        return net_response.json() if return_json else net_response.text()


    def get_preauth_context(self, params=None):
        """
        get required context information before the user is authenticated
        """
        if params is None:
            params = {}

        context = self.call_linotp('/userservice/pre_context', params=params)
        return context


    def get_context(self, params=None):
        """
        retrieve the selfservice defintion in the scope of the
        authenticated user
        """
        if params is None:
            params = {}
        context = self.call_linotp('/userservice/context', params=params)
        return context


    def set_language(self, headers):
        '''Invoke before everything else. And set the translation language'''
        languages = headers.get('Accept-Language', '')

        found_lang = False

        for match in accept_language_regexp.finditer(languages):
            # make sure we have a correct language code format
            language = match.group(1)
            if not language:
                continue
            language = language.replace('_', '-').lower()

            # en is the default language
            if language.split('-')[0] == 'en':
                found_lang = True
                break

            try:
                set_lang(language.split('-')[0])
                found_lang = True
                break
            except LanguageError:
                log.debug("Cannot set requested language: %s. Trying next language if available.",
                          language)

        if not found_lang:
            log.warning("Cannot set preferred language: %r" % languages)

        return

    def sendError(self, response, exception, errId=311, context=None):
        """
        return an error response to the client
        """
        version = get_version()
        id = '1.0'

        ## handle the different types of exception:
        ## Exception, LinOtpError, str/unicode
        if (hasattr(exception, '__class__') == True
            and isinstance(exception, Exception)):
                errDesc = unicode(exception)
        elif type(exception) in [str, unicode]:
            errDesc = unicode(exception)
        else:
            errDesc = u"%r" % exception

        response.content_type = 'application/json'
        res = { "jsonrpc": "2.0",
                "result" :
                    {"status": False,
                        "error": {
                            "code"    :   errId,
                            "message" :   errDesc,
                            },
                    },
                 "version": version,
                 "id": id
            }

        ret = json.dumps(res, indent=3)

        if context in ['before', 'after']:
            response._exception = exception
            response.body = ret
            ret = response

        return res
