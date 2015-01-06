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

from paste.httpexceptions import HTTPFound
from paste.httpexceptions import HTTPUnauthorized

from paste.request import parse_dict_querystring
import urlparse
import urllib
import cgi
import base64

from paste.request import parse_formvars

from zope.interface import implements

from repoze.who.interfaces import IChallenger
from repoze.who.interfaces import IIdentifier
from paste.response import header_value


from repoze.who.plugins.form import RedirectingFormPlugin as RepozeRedirectingFormPlugin
from repoze.who.plugins.form import make_plugin as repoze_make_plugin


class LinOTPRedirectingFormPlugin(RepozeRedirectingFormPlugin):
    """
    inherited redirect form plugin - extended to return the realm input value
    """

    implements(IChallenger, IIdentifier)

    def __init__(self, login_form_url, login_handler_path, logout_handler_path,
                 rememberer_name, reason_param='reason'):
        """
        instatiate the parent class but make the parent an accessible member
        """

        self.parent = super(LinOTPRedirectingFormPlugin, self)
        self.parent.__init__(login_form_url, 
                             login_handler_path, 
                             logout_handler_path,
                             rememberer_name, 
                             reason_param)

        self.logout_path = logout_handler_path

        return

    # IIdentifier
    def identify(self, environ):
        '''
        identifier hook to get the user/password/realm from the form and
        return the identifier + credentials

        remark: in contradiction to the parent.identity method, we set the 
                referer always to be root '/'

        :param environment: the request data as environment

        :return credentials: dict with login, password and realm if not None
        '''
        referer = environ.get('HTTP_REFERER', '/')
        credentials = self.parent.identify(environ)

        if credentials is not None:
            # in case we have no '@' in login
            # we extende the login to contain the realm if there is a valid one
            query = parse_dict_querystring(environ)
            form = parse_formvars(environ)
            form.update(query)

            if not "@" in credentials['login']:
                # get the realm from the form data
                

                if 'realm' in form and form['realm']:
                    credentials['login'] = "%s@%s" % (credentials['login'],
                                                      form['realm'])

            otp = base64.b32encode(form.get('otp', ''))
            passw = base64.b32encode(form['password'])
            password = "%s:%s" % (otp, passw)
            credentials['password'] = password

            environ['repoze.who.application'] = HTTPFound(referer)
        return credentials

    def challenge(self, environ, status, app_headers, forget_headers):
        '''
        the challenge method is implemented here to supress the came_from
        query_attribute, which is not welcomed here :-) 
        '''
        reason = header_value(app_headers, 'X-Authorization-Failure-Reason')

        # split the login url in host, url, ? , query
        url_parts = list(urlparse.urlparse(self.login_form_url))

        # here we extend the query to contain the reason as parameter 
        query = url_parts[4]
        query_elements = cgi.parse_qs(query)
        if reason:
            query_elements[self.reason_param] = reason

        # now rebuild the query string and the header
        url_parts[4] = urllib.urlencode(query_elements, doseq=True)
        login_form_url = urlparse.urlunparse(url_parts)

        headers = [ ('Location', login_form_url) ]
        cookies = [(h, v) for (h, v) in app_headers if h.lower() == 'set-cookie']
        headers = headers + forget_headers + cookies

        return HTTPFound(headers=headers)

def make_plugin(login_form_qs='__do_login',
                rememberer_name=None,
                form=None,
                formcallable=None,
               ):
    """
    who.ini hook to instantiate the form plugin
    - we use here the one of repoze.who.plugin.form
    """

    plugin = repoze_make_plugin(login_form_qs, rememberer_name, 
                              form, formcallable)
    return plugin

def make_redirecting_plugin(login_form_url="/account/login",
                            login_handler_path='/account/dologin',
                            logout_handler_path='/account/logout',
                            rememberer_name='auth_tkt'):
    """
    who.ini hook to instantiate the redirect form plugin
    """
    plugin = LinOTPRedirectingFormPlugin(login_form_url,
                                   login_handler_path,
                                   logout_handler_path,
                                   rememberer_name)
    return plugin

#eof###########################################################################