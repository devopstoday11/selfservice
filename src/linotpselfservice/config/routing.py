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

"""Routes configuration

The more specific and detailed routes should be defined first so they
may take precedent over the more generic routes. For more information
refer to the routes manual at http://routes.groovie.org/docs/
"""
from routes import Mapper

def make_map(config, global_conf, app_conf):
    """Create, configure and return the routes Mapper"""
    routeMap = Mapper(directory=config['pylons.paths']['controllers'],
                 always_scan=config['debug'])
    routeMap.minimization = False
    #routeMap.explicit = False

    # The ErrorController route (handles 404/500 error pages); it should
    # likely stay at the top, ensuring it can always be resolved
    routeMap.connect('/error/{action}', controller='error')
    routeMap.connect('/error/{action}/{id}', controller='error')

    # CUSTOM ROUTES HERE

    # in case of selfservice, we route the default / to selfservice
    selfservice = app_conf.get('service.selfservice', 'True') == 'True'
    if selfservice:
        routeMap.connect('/selfservice/custom-style.css', controller='selfservice', action='custom_style')
        routeMap.connect('/selfservice', controller='selfservice', action='index')
        routeMap.connect('/', controller='selfservice', action='index')
        for cont in ['selfservice', 'account', 'userservice']:
            routeMap.connect('/%s/{action}' % cont , controller=cont)
            routeMap.connect('/%s/{action}/{id}' % cont, controller=cont)


    return routeMap
