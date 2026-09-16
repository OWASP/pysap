# encoding: utf-8
# pysap - Python library for crafting SAP's network protocols packets
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from pysap.utils.console import BaseConsole


class BaseConsoleTest(unittest.TestCase):

    def make_console(self):
        console = BaseConsole(SimpleNamespace(
            consolelog=None, verbose=False))
        console.connected = True
        console.do_capture = mock.Mock()
        console.do_disconnect = mock.Mock(
            side_effect=lambda _: setattr(console, "connected", False))
        return console

    def test_script_ignores_comments_and_preserves_quoted_arguments(self):
        console = self.make_console()
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as script:
            script.write("# comment\n\n capture 'two words' plain\n")
            script.flush()

            console.do_script(script.name)

        console.do_capture.assert_called_once_with("'two words' plain")

    def test_script_lifecycle_disconnects_and_closes_console(self):
        console = self.make_console()
        console.preloop = mock.Mock()
        console.do_script = mock.Mock()
        console.postloop = mock.Mock()

        self.assertTrue(console.run_script("commands.txt"))

        console.preloop.assert_called_once_with()
        console.do_script.assert_called_once_with("commands.txt")
        console.do_disconnect.assert_called_once_with(None)
        console.postloop.assert_called_once_with()

    def test_script_lifecycle_skips_commands_after_failed_connect(self):
        console = self.make_console()
        console.connected = False
        console.preloop = mock.Mock()
        console.do_script = mock.Mock()
        console.postloop = mock.Mock()

        self.assertFalse(console.run_script("commands.txt"))

        console.do_script.assert_not_called()
        console.do_disconnect.assert_not_called()
        console.postloop.assert_called_once_with()

    def test_completion_helpers_normalize_and_filter_values(self):
        self.assertEqual(BaseConsole._complete_values("1", [2, 10, 11]),
                         ["10", "11"])
        self.assertEqual(BaseConsole._completion_arg("command first ", 14),
                         1)


if __name__ == "__main__":
    unittest.main()
