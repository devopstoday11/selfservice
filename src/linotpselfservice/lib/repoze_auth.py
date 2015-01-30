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
import urllib
import os

import traceback
import logging

from zope.interface import implements

from repoze.who.interfaces import IAuthenticator
from repoze.who.interfaces import IMetadataProvider

from paste.request import parse_dict_querystring

from linotpselfservice.lib.network import Connection

log = logging.getLogger(__name__)


class LinOTPUserAuthPlugin(object):

    implements(IAuthenticator)

    def __init__(self, linotp_url, client_cert=None, client_key=None, server_cert=None):
        self.conn = None

        self.base_url = linotp_url

        # load keyfile
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
        self.server_cert = None
        # replace the app root %here% if any
        if server_cert and '%(here)s' in server_cert:
            server_cert = server_cert.replace('%(here)s', self.here)

        if server_cert:
            if os.path.exists(server_cert):
                self.server_cert = server_cert
            else:
                log.error("cert_file %s could not be found", server_cert)


    # IAuthenticatorPlugin
    def authenticate(self, environ, identity):
        try:
            login = identity['login']
            password = identity['password']
        except KeyError:
            return None

        try:
            if not self.conn:
                self.conn = Connection(
                    self.base_url,
                    server_cert=self.server_cert,
                    client_cert=self.client_cert,
                    client_key=self.client_key
                    )
            params = {'login':login, 'password': password}
            headers = {"Content-type": "application/x-www-form-urlencoded",
                       "Accept": "text/plain"}

            if environ.get('HTTP_ACCEPT_LANGUAGE', None):
                headers['Accept-Language'] = environ.get('HTTP_ACCEPT_LANGUAGE', None)

            path = "/userservice/auth"

            net_response = self.conn.post(path, params=params, headers=headers)

            if net_response.status_code != 200:
                return None

            res = net_response.json()
            authUser = res.get('result', {}).get('value', False)
            if authUser != False:
                cookie = net_response.get_cookie('userauthcookie')
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
                            id(self))


class LinOTPUserModelPlugin(LinOTPUserAuthPlugin):

    implements(IMetadataProvider)

    def __init__(self, linotp_url, client_cert=None, client_key=None, server_cert=None):
        self.parent = super(LinOTPUserModelPlugin, self)
        self.parent.__init__(linotp_url, client_cert, client_key, server_cert)

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
            if not self.conn:
                self.conn = Connection(
                    self.base_url,
                    server_cert=self.server_cert,
                    client_cert=self.client_cert,
                    client_key=self.client_key
                    )

            if not self.conn.is_user_session_set:
                # for the authetication we take the 'repoze.who.userid' as it
                # is the one which is returned from the authenticate call
                # extended by the realm and joined with the auth_cookie
                if ';' in identity['repoze.who.userid']:
                    user, session = identity['repoze.who.userid'].split(';', 1)
                    self.conn.set_user_session(session, user)
                else:
                    user = identity['repoze.who.userid']
                    self.conn.set_user_session(None, user)

            path = "/remoteservice/userinfo"
            response = self.conn.post(path, params=params, headers=headers)

            if response.status_code == 200:
                res = response.json()
                user_data = res.get('result', {}).get('value',[])
                if type(user_data) in [dict]:
                    identity.update(user_data)

                # implicit return of enriched identity
                return identity

        except Exception as exx:
            log.error("[add_metadata] %r" % exx)
            raise exx

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__,
                            id(self))

def make_auth_plugin(
        linotp_url,
        client_cert=None,
        client_key=None,
        server_cert=None
        ):
    # we could check here, if the cert and key file are avail and accessible
    try:
        plugin = LinOTPUserAuthPlugin(
            linotp_url,
            client_cert=client_cert,
            client_key=client_key,
            server_cert=server_cert
            )
    except Exception as exx:
        raise exx
    return plugin

def make_modl_plugin(
        linotp_url,
        client_cert=None,
        client_key=None,
        server_cert=None
        ):
    # we could check here, if the cert and key file are avail and accessible
    try:
        plugin = LinOTPUserModelPlugin(
            linotp_url,
            client_cert=client_cert,
            client_key=client_key,
            server_cert=server_cert
            )
    except Exception as exx:
        raise exx
    return plugin
