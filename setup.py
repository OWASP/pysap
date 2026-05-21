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
from pathlib import Path
from setuptools import setup, Command
from setuptools._distutils.errors import DistutilsExecError


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
        """Run Sphinx."""
        try:
            from sphinx.cmd.build import main as sphinx_build
        except ImportError as exc:
            raise DistutilsExecError(
                "Sphinx is required to build the documentation. "
                "Install the docs extra first: python3 -m pip install pysap[docs]"
            ) from exc

        docs_dir = Path("docs")
        build_dir = docs_dir / "_build"
        argv = [
            "-b", "html",
            "-d", str(build_dir / "doctrees"),
            str(docs_dir),
            str(build_dir / "html"),
        ]
        self.announce("building documentation with Sphinx", level=2)
        status = sphinx_build(argv)
        if status:
            raise DistutilsExecError("Sphinx build failed with status %d" % status)


class PreExecuteNotebooksCommand(Command):
    """Custom command for pre-executing Jupyter notebooks included in the documentation.
    """

    description = "Pre-executes Jupyter notebooks included in the documentation"
    user_options = [
        ('notebooks=', 'n', "patterns to match (i.e. 'protocols/SAPDiag*')"),
        ('timeout=', 't', "execution timeout in seconds for each notebook"),
        ('kernel-name=', 'k', "Jupyter kernel name to use"),
        ('allow-errors', None, "keep executing notebooks when a cell raises an error"),
        ('clean', None, "clear code cell outputs and execution metadata after execution"),
    ]
    boolean_options = ['allow-errors', 'clean']

    def initialize_options(self):
        """Initialize options with default values."""
        self.notebooks = None
        self.timeout = None
        self.kernel_name = None
        self.allow_errors = False
        self.clean = False

    def finalize_options(self):
        """Check and expand provided values."""
        docs_dir = Path("docs")
        if self.notebooks:
            notebooks = sorted(docs_dir.glob(self.notebooks))
        else:
            notebooks = sorted(docs_dir.glob("protocols/*.ipynb"))
            notebooks.extend(sorted(docs_dir.glob("fileformats/*.ipynb")))
        self.notebooks = notebooks
        if not self.notebooks:
            raise DistutilsExecError("No notebooks matched the requested pattern")

        self.timeout = int(self.timeout) if self.timeout is not None else 600
        self.kernel_name = self.kernel_name or "python3"

    def run(self):
        """Pre-execute notebooks in place."""
        try:
            import nbformat
            from nbconvert.preprocessors import ExecutePreprocessor
        except ImportError as exc:
            raise DistutilsExecError(
                "nbformat and nbconvert are required to execute notebooks. "
                "Install the docs extra first: python3 -m pip install pysap[docs]"
            ) from exc

        for notebook in self.notebooks:
            self.announce("executing notebook %s" % notebook, level=2)
            with notebook.open("r", encoding="utf-8") as fh:
                nb = nbformat.read(fh, as_version=nbformat.NO_CONVERT)

            executor = ExecutePreprocessor(
                timeout=self.timeout,
                kernel_name=self.kernel_name,
                allow_errors=self.allow_errors,
            )
            resources = {"metadata": {"path": str(notebook.parent)}}
            try:
                executor.preprocess(nb, resources=resources)
            except Exception as exc:
                raise DistutilsExecError("Notebook execution failed for %s" % notebook) from exc

            if self.clean:
                self.announce("cleaning executed cells from notebook %s" % notebook, level=2)
                self.clean_notebook(nb)

            with notebook.open("w", encoding="utf-8") as fh:
                nbformat.write(nb, fh)

    @staticmethod
    def clean_notebook(nb):
        """Clear outputs and execution metadata from code cells."""
        for cell in nb.cells:
            if cell.cell_type == "code":
                cell.outputs = []
                cell.execution_count = None
                cell.metadata.pop("execution", None)



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

      # Pure Python compression module
      py_modules=['pysapcompress'],

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
