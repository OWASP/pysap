.. Internet Graphic Service example scripts

Internet Graphic Service Example scripts
========================================

``igs_http_imgconv``
--------------------

This example script demonstrates the use of the ``IGS`` interpreter ``IMGCONV`` through HTTP
listener to convert a provided ``jpg`` file to the ``png`` format with a 100x100 size.
The input image defaults to ``poc.jpg`` and can be changed with ``--image``.

.. code-block:: console

    $ examples/igs_http_imgconv.py -d <igs-host> -p 40080 --image input.jpg


``igs_http_xmlchart``
---------------------

This example script demonstrates the use of the ``IGS`` interpreter through HTTP listener
to generate a simple chart. The input of the chart is provided in ``XML`` format and the
script will print the generated charts' URLs.

.. code-block:: console

    $ examples/igs_http_xmlchart.py -d <igs-host> -p 40080


``igs_http_zipper``
-------------------

This example script demonstrates the use of the ``IGS`` interpreter ``ZIPPER`` through HTTP
listener to compress an input file to a ``zip`` file. The script will print the generated
``zip`` files URLs. The input file defaults to ``poc.txt`` and can be changed with ``-i``.
Use ``-a`` to choose the path stored inside the generated archive.

.. code-block:: console

    $ examples/igs_http_zipper.py -d <igs-host> -p 40080 -i input.txt -a docs/input.txt


``igs_rfc_zipper``
------------------

This example script demonstrates the use of the ``IGS`` interpreter ``ZIPPER`` through RFC
listener to compress an input file to a ``zip`` file. The input file defaults to ``poc.txt``
and can be changed with ``-i``. Use ``-a`` to choose the path stored inside the generated
archive.

.. code-block:: console

    $ examples/igs_rfc_zipper.py -d <igs-host> -p 40000 -i input.txt -a docs/input.txt
