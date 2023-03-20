# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import pysap
version = pysap.__version__
release = version
project = 'pysap'
copyright = 'Martin Gallo, OWASP CBAS Project'
author = 'Martin Gallo, OWASP CBAS Project'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinxcontrib.apidoc",
    "nbsphinx",
    "m2r",
]

templates_path = ['_templates']
exclude_patterns = ['_build', '**.ipynb_checkpoints']



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']


# -- API Doc configuration
apidoc_module_dir = "../pysap"
apidoc_output_dir = "api/"
apidoc_separate_modules = True
apidoc_toc_file = False
apidoc_module_first = True
