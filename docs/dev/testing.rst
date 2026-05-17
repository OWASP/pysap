Testing guide
=============

The test suite is split into small, deterministic unit tests and a narrower
integration layer for socket-backed protocol paths. The current harness is
designed to run in the local development environment, in CI, and in restricted
sandboxes without changing the test code.

Test layers
-----------

Unit tests
  Fast tests that exercise packet helpers, file-format parsers, and client
  logic with fake transports or in-memory fixtures. These are the default
  regression tests and should stay deterministic.

Integration tests
  Tests that need a listening socket or more realistic transport behavior.
  They are marked with ``integration`` and are skipped automatically when the
  environment cannot bind sockets.

Core test suites
----------------

The current test coverage is centered on these modules:

* ``tests/fields_test.py`` covers reusable field helpers in ``pysap.utils.fields``.
* ``tests/sapsnc_test.py`` covers SNC frame wrapping and unwrapping logic.
* ``tests/saplps_test.py`` covers the LPS cipher dispatch and error paths.
* ``tests/sapdiagclient_test.py`` covers client setup, send/receive flow, and
  support-data normalization.
* ``tests/sapenqueue_test.py`` covers enqueue packet helpers and stream
  reassembly.
* ``tests/sapigs_test.py`` covers IGS packet construction and request helpers.
* ``tests/sapms_test.py`` covers representative message-server packet types.
* ``tests/saprfc_test.py`` covers RFC packet variants and field handling.
* ``tests/sapcar_test.py``, ``tests/sapcredv2_test.py``, ``tests/sappse_test.py``,
  and ``tests/sapssfs_test.py`` cover the file-format and crypto-oriented paths.
* ``tests/sapdiag_test.py``, ``tests/sapni_test.py``, ``tests/saprouter_test.py``,
  and ``tests/saphdb_test.py`` cover protocol packet handling, with the socket
  heavy cases marked as integration.

Harness behavior
----------------

The test harness uses ``tests/conftest.py`` to keep collection stable across
environments. It disables Scapy interface probing during test discovery and
skips integration-marked tests when socket binding is not available.

Shared helpers live in ``tests/utils.py``. The current helpers provide packet
round-trip checks and a dummy connection object for tests that only need to
exercise protocol logic.

Recommended commands
--------------------

Run the full unit suite with tox::

   $ python3 -m tox -e unit

Run the integration suite separately::

   $ python3 -m tox -e integration

If you are iterating on a single module, pytest can target it directly::

   $ python3 -m pytest tests/saplps_test.py

Writing tests
-------------

Keep new tests at the smallest useful scope. Prefer fake sockets, small packet
fixtures, and round-trip assertions over live network dependencies unless the
behavior truly requires them.

Good additions usually follow these rules:

* one behavior per test;
* deterministic inputs and outputs;
* negative-path coverage for invalid versions, malformed fields, and error
  handling;
* integration markers only for code that must bind sockets or talk to a live
  service.

Coverage tends to improve fastest when tests focus on helper functions and
packet builders first, then move outward to transport wrappers and
socket-backed flows.
