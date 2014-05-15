## ===========
## pysap - Python library for crafting SAP's network protocols packets
##
## Copyright (C) 2014 Core Security Technologies
##
## The library was designed and developed by Martin Gallo from the Security
## Consulting Services team of Core Security Technologies.
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 2
## of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##==============

# Standard imports
from os import path, makedirs, system
from setuptools import setup, Extension, Command


name = "pysap"
url = "http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=pysap"


class APIDocumentationCommand(Command):
    """
    Custom command for building API documentation with epydoc.

    @requires: epydoc installed

    """

    description = "Builds the API documentation using epydoc"
    user_options = []
    target_dir = "./doc/"

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        """
        Runs epydoc
        """
        if not path.exists(self.target_dir):
            makedirs(self.target_dir)

        target = "pysap pysapcompress"
        system('epydoc --graph all --html --name "%s" --url "%s" -v -o %s %s' % (name, url, self.target_dir, target))


sapcompress = Extension('pysapcompress',
                         ['pysapcompress/pysapcompress.cpp',
                          'pysapcompress/vpa105CsObjInt.cpp',
                          'pysapcompress/vpa106cslzc.cpp',
                          'pysapcompress/vpa107cslzh.cpp',
                          'pysapcompress/vpa108csulzh.cpp'],
                         define_macros=[  # Enable this macro if you want some debugging information on the (de)compression functions
                                        #('DEBUG', None),
                                          # Enable this macro if you want detailed debugging information (hexdumps) on the (de)compression functions
                                        #('DEBUG_TRACE', None),
                                        ])


description = \
"""
pysap - Python library for communicating using SAP network protocols.

Currently the following SAP protocols are included:
- SAP NI (Network Interface).
- SAP Diag.
- SAP Enqueue Server.
- SAP Message Server.
- SAP Router.
- SAP RFC.
"""


setup(  # Package information
        name=name,
        version='0.1.5',
        author='Martin Gallo',
        author_email='mgallo@coresecurity.com',
        description='Python library for crafting SAP\'s network protocols packets',
        long_description=description,
        url=url,
        download_url=url,
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Intended Audience :: Developers',
            'Intended Audience :: Information Technology',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
            'Programming Language :: Python',
            'Programming Language :: C++',
            'Topic :: Security',
            ],

        # Packages list
        packages=['pysap'],
        provides=['pysapcompress', 'pysap'],

        # Extension module compilation
        ext_modules=[sapcompress],

        # Tests command
        test_suite='tests.suite',

        # API Documentation command
        cmdclass={'doc': APIDocumentationCommand},
        )
