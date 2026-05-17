#!/usr/bin/env python3
# encoding: utf-8
# pysap - Python library for crafting SAP's network protocols packets
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
#
# Author:
#   Martin Gallo (@martingalloar)
#   Code contributed by SecureAuth to the OWASP CBAS project
#

# Standard imports
import re
from sys import exit
from glob import glob
from subprocess import call
from setuptools import setup, Extension, Command


def read_metadata(name):
    """Read a package metadata value from pysap/__init__.py without importing it."""
    with open("pysap/__init__.py", "r", encoding="utf-8") as fh:
        content = fh.read()
    match = re.search(r"^%s\s*=\s*['\"]([^'\"]+)['\"]" % re.escape(name), content, re.MULTILINE)
    if not match:
        raise RuntimeError("Unable to find %s in pysap/__init__.py" % name)
    return match.group(1)


class DocumentationCommand(Command):
    """Custom command for building the documentation with Sphinx.
    """

    description = "Builds the documentation using Sphinx"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        """Runs Sphinx
        """
        exit(call("cd docs && make html", shell=True))


class PreExecuteNotebooksCommand(Command):
    """Custom command for pre-executing Jupyther notebooks included in the documentation.
    """

    description = "Pre-executes Jupyther notebooks included in the documentation"
    user_options = [
        ('notebooks=', 'n', "patterns to match (i.e. 'protocols/SAPDiag*')"),
    ]

    def initialize_options(self):
        """Initialize options with default values."""
        self.notebooks = None

    def finalize_options(self):
        """Check and expand provided values."""
        base_path = "docs/"
        if self.notebooks:
            self.notebooks = glob(base_path + self.notebooks)
        else:
            self.notebooks = glob(base_path + "protocols/*.ipynb")
            self.notebooks.extend(glob(base_path + "fileformats/*.ipynb"))

    def run(self):
        """Pre executes notebooks."""
        status = 0
        for notebook in self.notebooks:
            status |= call("jupyter nbconvert --inplace --to notebook --execute {}".format(notebook), shell=True)
        exit(status)


sapcompress_macros = [
    # Enable this macro if you want some debugging information on the (de)compression functions
    # ('DEBUG', None),
    # Enable this macro if you want detailed debugging information (hexdumps) on the (de)compression functions
    # ('DEBUG_TRACE', None),
]


sapcompress = Extension('pysapcompress',
                        ['pysapcompress/pysapcompress.cpp',
                         'pysapcompress/vpa105CsObjInt.cpp',
                         'pysapcompress/vpa106cslzc.cpp',
                         'pysapcompress/vpa107cslzh.cpp',
                         'pysapcompress/vpa108csulzh.cpp'],
                        define_macros=sapcompress_macros)


with open("README.md", "r") as fh:
    long_description = fh.read()


setup(name=read_metadata("__title__"),  # Package information
      version=read_metadata("__version__"),
      author='Martin Gallo, OWASP CBAS Project',
      author_email='martin.gallo@gmail.com',
      description='Python library for crafting SAP\'s network protocols packets',
      long_description=long_description,
      long_description_content_type="text/markdown",
      url=read_metadata("__url__"),
      download_url=read_metadata("__url__"),
      license=read_metadata("__license__"),
      classifiers=['Development Status :: 3 - Alpha',
                   'Intended Audience :: Developers',
                   'Intended Audience :: Information Technology',
                   'Intended Audience :: System Administrators',
                   'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
                   'Programming Language :: Python :: 3',
                   'Programming Language :: Python :: 3 :: Only',
                   'Programming Language :: Python :: 3.10',
                   'Programming Language :: Python :: 3.11',
                   'Programming Language :: Python :: 3.12',
                   'Programming Language :: Python :: 3.13',
                   'Programming Language :: Python :: 3.14',
                   'Programming Language :: C++',
                   'Topic :: Security'],
      python_requires='>=3.10',
      # Packages list
      packages=['pysap', 'pysap.utils', 'pysap.utils.crypto'],
      provides=['pysapcompress', 'pysap'],

      # Extension module compilation
      ext_modules=[sapcompress],

      # Script files
      scripts=['bin/pysapcar', 'bin/pysapgenpse'],

      # Documentation commands
      cmdclass={'doc': DocumentationCommand,
                'notebooks': PreExecuteNotebooksCommand},

      # Requirements
      install_requires=open('requirements.txt').read().splitlines(),

      # Optional requirements for docs and some examples
      extras_require={"tests": open('requirements-test.txt').read().splitlines(),
                      "docs": open('requirements-docs.txt').read().splitlines(),
                      "examples": open('requirements-examples.txt').read().splitlines()},
      )
