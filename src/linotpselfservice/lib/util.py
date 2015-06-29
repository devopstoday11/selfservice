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

from linotpselfservice import __version__ as version

import logging
log = logging.getLogger(__name__)

SESSION_KEY_LENGTH = 32

def check_selfservice_session(request):
    '''
    This function checks the session cookie for the
    selfservcice session
    '''
    res = True
    cookie = None
    session = None

    log.debug(request.path.lower())

    cookie = request.cookies.get('linotp_selfservice')[0:40]
    session = request.params.get('session')[0:40]

    if session is None or session != cookie:
        log.error("The request %s did not pass a valid session!" % request.url)
        res = False

    return res

def get_version_number():
    '''
    returns the linotp version
    '''
    return version

def get_version():
    '''
    This returns the version, that is displayed in the WebUI and self service portal.
    '''
    version = get_version_number()
    return "LinOTP SelfService %s" % version
