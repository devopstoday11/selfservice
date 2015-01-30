"""
This module is basically a 'requests' wrapper to make it easier to deal with
different requests versions.
"""

import requests
import logging
from urlparse import urlparse

LOG = logging.getLogger(__name__)

class Connection(object):
    """
    Represents a HTTP connection that can send requests repeatedly. It is
    basically a wrapper for a requests.Session object.
    """
    def __init__(
            self,
            base_url,
            server_cert=None,
            client_cert=None,
            client_key=None
            ):
        """
        Creates a Connection object.

        :param base_url: Base URL of the type https://myserver.com/
        :type base_url: string
        :param server_cert: Path to a server certificate
        :type server_cert: string
        :param client_cert: Path to a client certificate
        :type client_cert: string
        :param client_key: Path to a client key
        :type client_key: string
        """
        self._session = requests.Session()
        self.base_url = base_url
        url_parts = urlparse(base_url)
        protocol = url_parts[0].lower()
        if protocol == 'https':
            if server_cert and client_cert and client_key:
                self._session.verify = server_cert
                self._session.cert = (client_cert, client_key)
            else:
                LOG.warning("Using https without certificates is a security risk.")
        else:
            LOG.warning("Using http is a security risk.")
        self.is_user_session_set = False

    def set_user_session(self, session, user):
        """
        This is an optional convenience method that can be used to set the
        session parameter, session cookie and user parameter for the complete
        lifetime of the Connection object.
        It takes advantage of the fact that requests.Session can store default
        values that are added to every request. This is even more true for
        Cookies, which are stored automatically in the Session object if any
        request returns a Cookie.
        The values are overwritten if something of the same name is supplied
        when making a request.

        :param session: A session string that will be included as default value
            in every request as a parameter and that will be used to create a
            Cookie 'userauthcookie'=session
            If the value is falsy it is not appended and no Cookie is created.
            It only sets default values, that are overwritten by values passed
            in when making the request (e.g.  calling post() method).
        :type session: string
        :param user: The user. It only sets a default value, that is
            overwritten by values passed in when making the request (e.g.
            calling post() method).
        :type user: string
        """
        if session:
            self._session.params.update(dict(session=session))
            self._session.cookies.set('userauthcookie', session)
        if user:
            self._session.params.update(dict(user=user))
        if session or user:
            self.is_user_session_set = True

    def post(self, path, params=None, headers=None):
        """
        Send a POST request to self.base_url + path.

        :param path: The URL part following the base_url
        :type path: string
        :param params: Parameters for the request
        :type params: dict
        :param headers: Headers for the request
        :type headers: dict
        """
        response = self._session.post(
            self.base_url + path,
            params=params,
            headers=headers,
            )
        return Response(response)
        

class Response(object):
    """
    Represents a HTTP response object (wrapper for requests.Response).
    """
    def __init__(self, response):
        """
        Creates a Response() object.

        :param response: A requests.Response object to be wrapped
        :type response: requests.Response
        """
        self._response = response

    @property
    def status_code(self):
        return self._response.status_code

    @property
    def reason(self):
        return self._response.reason

    def json(self):
        return self._response.json()

    def text(self):
        return self._response.text

    def get_cookie(self, name):
        return self._response.cookies[name]
