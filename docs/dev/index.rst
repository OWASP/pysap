.. Development guide frontend

Development
===========

If you are interested in contribute to the project, this part of the
documentation should contain the start point.

.. toctree::
   :maxdepth: 2
   :glob:

   *

Documentation
-------------

Documentation can be build using::

    $ python setup.py doc

A build is also available at `Read the Docs <https://pysap.readthedocs.io/en/latest/>`_.


The build process requires several packages and libraries to be available. The operative system libraries required are:

* ``pandoc``
* A LaTex environment, for example ``TexLive`` on Linux or ``MikTex`` on Windows.

For example, installation on a Ubuntu box would require the following commands::

    $ sudo apt install pandoc texlive-latex-base

Python packages can be installed using ::

    $ pip install pysap[docs]


Notebooks
---------

Documentation include a graphical representation of the most commonly used protocol packets and file formats. This
graphical representations are built using `Scapy <https://scapy.net/>`_,
`The Jupyter Notebook <https://ipython.org/notebook.html>`_ , `nbconvert <https://github.com/jupyter/nbconvert>`_ and
`nbsphinx <https://github.com/spatialaudio/nbsphinx/>`_.

Jupyter notebooks containing the protocol packets' representation can be re-build using the following command::

   $ python setup.py notebooks


Code contributions
------------------

When contributing code, follow this checklists:

1. Fork the repository on `GitHub <https://github.com/SecureAuthCorp/pysap/>`_.
2. Run the tests to check that all current tests pass on the system. If they don't,
   some investigation might be required to determine why they fail. Note that current
   tests are limited and only covers some of the protocols and client interfaces.
3. If possible, write tests that demonstrate the bug you're fixing or the feature
   being added.
4. Make the desired changes.
5. Run the tests again and ensure they are passing again and remain valid.
6. Send a GitHub Pull Request to the repository's master branch.


Bug reporting
-------------

Bug reports are important to keep the project up. It's important to clarify that
examples are not mean to be valid for all current software versions, and in most of
the cases they are demonstrations over the capabilities of having the packages
implemented in the library. However, improvements are highly appreciated on both
library's core components and example scripts.

When submitting bugs, follow this checklist:

1. Check current `GitHub issues <https://github.com/SecureAuthCorp/pysap/issues>`_ for
   potential duplicates.
2. Create a new issue detailing as much information as possible. Packet captures are
   always helpful when dealing with specific packets missing or client interface errors.
