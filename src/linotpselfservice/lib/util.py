
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
