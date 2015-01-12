"""The base Controller API

Provides the BaseController class for subclassing.
"""

from pylons import request, response, tmpl_context as c

from pylons.controllers import WSGIController
from pylons.i18n.translation import set_lang
from pylons.i18n import LanguageError

from linotpselfservice.config.environment import app_config
from linotpselfservice.lib.util import get_version

from urlparse import urlparse
import json

import httplib
import urllib
import os

import traceback
import logging


log = logging.getLogger(__name__)

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
            url = self.config['linotp_url']
        except KeyError:
            raise Exception("Missing definition of remote linotp url in application ini: linotp_url")

        url_parts = urlparse(url)
        self.proto = url_parts[0]

        if self.proto == 'http':
            self.port = 80
        elif self.proto == 'https':
            self.port = 443

        self.host = url_parts[1]
        if ':' in self.host:
            self.host, self.port = self.host.split(':')

        self.path = url_parts[2]

        # load keyfile
        self.key = None
        key = self.config.get('linotp_keyfile', None)

        # replace the app root here if any
        if key and '%(here)s' in key:
            key = key.replace('%(here)s', self.here)

        if key and os.path.exists(key):
            self.key = key

        # load the certificate file
        self.cert = None
        cert = self.config.get('linotp_certfile', None)
        # replace the app root here if any
        if cert and '%(here)s' in cert:
            cert = cert.replace('%(here)s', self.here)

        if cert and os.path.exists(cert):
            self.cert = cert

        self.remote_base = self.config.get('linotp_remote_base', '/userservice')

        return

    def __connect__(self):
        if self.conn is None:
            param = {}
            param['host'] = self.host
            param['port'] = self.port

            if self.cert is not None:
                # if there is no cert - we use a simple http connection
                param['cert_file'] = self.cert

            if self.key is not None:
                # if there is no cert - we use a simple http connection
                param['key_file'] = self.key

            if self.proto in ['https']:
                self.conn = httplib.HTTPSConnection(**param)
            else:
                self.conn = httplib.HTTPConnection(**param)

        return self.conn


    def call_linotp(self, url, params=None, return_json=True):
        """
        make a http request to the linotp server

        :param url: the path of the linotp resource
        :param params: dict with request parameters
        :param return_json: bool, response should already be a json loaded obj

        :return: return the response of the request as dict or as plain text

        """
        self.conn = self.__connect__()

        if params is None:
            params = {}

        headers = {"Content-type": "application/x-www-form-urlencoded",
                   "Accept": "text/plain",
                   }

        # for locale support, we copy the incomming languege settings
        if self.browser_language:
            headers['Accept-Language'] = self.browser_language

        # if we are requesting for a user, provide the user auth cookie
        if 'user' in params:
            if hasattr(self, 'auth_cookie') and self.auth_cookie:
                headers['Cookie'] = self.auth_cookie
                params['session'] = self.auth_cookie.split(';')[0].split('=')[1]

        path = url

        self.conn.request('POST', path, urllib.urlencode(params), headers)
        response = self.conn.getresponse()

        if response.status != httplib.OK:
            error = "%s: %s - %s" % (path, response.status, response.reason)
            log.error(error)
            raise httplib.HTTPException(error)

        if return_json is False:
            return response.read()
        else:
            return json.loads(response.read())


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
        languages = headers.get('Accept-Language', '').split(';')

        found_lang = False

        for language in languages:
            for lang in language.split(','):
                try:
                    if lang[:2] == "en":
                        found_lang = True
                        break
                    if lang == 'de':
                        pass
                    set_lang(lang)
                    found_lang = True
                    break
                except LanguageError as exx:
                    pass

            if found_lang is True:
                break

        if found_lang is False:
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
