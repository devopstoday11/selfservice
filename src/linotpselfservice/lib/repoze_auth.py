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
""" user authentication with repoze module """


from urlparse import urlparse
import json
import httplib
import urllib
import os

import traceback
import logging

from zope.interface import implements

from repoze.who.interfaces import IAuthenticator
from repoze.who.interfaces import IMetadataProvider

from paste.request import parse_dict_querystring

log = logging.getLogger(__name__)


class LinOTPUserAuthPlugin(object):

    implements(IAuthenticator)

    def __init__(self, url, cert_file=None, key_file=None):
        self.conn = None

        url_parts = urlparse(url)
        self.proto = url_parts[0]

        if self.proto == 'http':
            self.port = 80
        elif self.proto == 'https':
            self.port = 443

        self.host = url_parts[1]
        if ':' in self.host:
            self.host,self.port = self.host.split(':')
 
        self.path = url_parts[2]

        # load keyfile
        self.key = None
        key = key_file
        # replace the app root %here% if any
        if key and '%(here)s' in key:
            key = key.replace('%(here)s', self.here)
        
        if key:
            if os.path.exists(key):
                self.key = key
            else:
                log.error("key_file %s could not be found", key)

        # load the certificate file
        self.cert = None
        cert = cert_file
        # replace the app root %here% if any
        if cert and '%(here)s' in cert:
            cert = cert.replace('%(here)s', self.here)

        if cert:
            if os.path.exists(cert):
                self.cert = cert
            else:
                log.error("cert_file %s could not be found", cert)


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

    # IAuthenticatorPlugin
    def authenticate(self, environ, identity):
        try:
            login = identity['login']
            password = identity['password']
        except KeyError:
            return None

        try:
            self.conn = self.__connect__()
            params = urllib.urlencode({'login':login, 'password': password})
            headers = {"Content-type": "application/x-www-form-urlencoded",
                       "Accept": "text/plain"}

            if environ.get('HTTP_ACCEPT_LANGUAGE', None):
                headers['Accept-Language'] = environ.get('HTTP_ACCEPT_LANGUAGE', None)

            path = "/userservice/auth"

            self.conn.request('POST', path, params, headers)
            response = self.conn.getresponse()
            content = response.read()

            if response.status != httplib.OK:
                return None

            res = json.loads(content)
            authUser = res.get('result',{}).get('value',False)
            if authUser != False:
                cookie = get_cookie(response)
                if cookie:
                    return "%s;%s" % (login, cookie)
                else:
                    return login
            return None

        except Exception as exx:
            log.error("[authenticate] %r" % exx)
            raise exx

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__,
                            id(self)) #pragma NO COVERAGE

def get_cookie(response):
    cookie = ''
    headers = response.getheaders()
    for head in headers:
        (key, value) = head
        if key == 'set-cookie':
            cookie = value
    return cookie


class LinOTPUserModelPlugin(LinOTPUserAuthPlugin):

    implements(IMetadataProvider)

    def __init__(self, url, cert_file=None, key_file=None):
        self.parent = super(LinOTPUserModelPlugin, self)
        self.parent.__init__(url, cert_file, key_file)

    # IMetadataProvider
    def add_metadata(self, environ, identity):
        """
        Add metadata about the authenticated user to the identity.
        
        It modifies the C{identity} dictionary to add the metadata.
        
        @param environ: The WSGI environment.
        @param identity: The repoze.who's identity dictionary.
        """

        params = {}
        headers = {"Content-type": "application/x-www-form-urlencoded", 
                   "Accept": "text/plain"}

        # this part is used implicit: on logout, there is no login and thus
        # just returns a None
        try:
            login = identity['login']
        except KeyError:
            return None

        try:
            self.conn = self.__connect__()

            # for the authetication we take the 'repoze.who.userid' as it
            # is the one which is returned from the authenticate call
            # extended by the realm and joined with the auth_cookie
            if ';' in identity['repoze.who.userid']:
                user, cookie = identity['repoze.who.userid'].split(';',1)
                headers['Cookie'] = cookie
            else:
                user = identity['repoze.who.userid']
            params['user'] = user

            path = "/remoteservice/userinfo"
            self.conn.request('POST', path, urllib.urlencode(params), headers)
            response = self.conn.getresponse()
            content = response.read()

            if response.status == httplib.OK:
                res = json.loads(content)
                user_data = res.get('result',{}).get('value',[])
                if type(user_data) in [dict]:
                    identity.update(user_data)

                # implicit return of enriched identity
                return identity

        except Exception as exx:
            log.error("[add_metadata] %r" % exx)
            raise exx

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__,
                            id(self)) #pragma NO COVERAGE

def make_auth_plugin(url, cert_file=None, key_file=None):
    # we could check here, if the cert and key file are avail and accessible
    try:
        plugin = LinOTPUserAuthPlugin(url, cert_file, key_file)
    except Exception as exx:
        raise exx
    return plugin

def make_modl_plugin(url, cert_file=None, key_file=None):
    # we could check here, if the cert and key file are avail and accessible
    try:
        plugin = LinOTPUserModelPlugin(url, cert_file, key_file)
    except Exception as exx:
        raise exx
    return plugin
