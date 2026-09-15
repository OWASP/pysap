# encoding: utf-8
# pysap - Python library for crafting SAP's network protocols packets
# SPDX-License-Identifier: GPL-2.0-or-later

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from pysap.SAPNI import SAPNI
from pysap.SAPRouter import SAPRouter
from examples import router_fingerprint as fingerprint


class RouterFingerprintTest(unittest.TestCase):

    def database(self, rows):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "fingerprints.json"
        path.write_text(json.dumps(rows), encoding="utf-8")
        return fingerprint.FingerprintDB(str(path))

    def test_partial_match_penalizes_missing_observed_fields(self):
        db = self.database({"No route": [{"release": "916", "module": "n.cpp",
                                           "line": "4004", "return_code": "-93",
                                           "error": "internal error"}]})
        partial = {"outcome": "router_error", "fields": {
            "release": "916", "module": "n.cpp", "line": "4004"}}
        first_score = db.match_fingerprint_scores("No route", partial)[0][1]
        self.assertLess(first_score, 0.75)
        partial["fields"].update(return_code="-93", error="other")
        improved_score = db.match_fingerprint_scores("No route", partial)[0][1]
        self.assertGreater(improved_score, first_score)

    def test_blank_rows_and_non_error_outcomes(self):
        db = self.database({"Network packet too big": [
            {"outcome": "eof", "release": "916"},
            {"release": "916", "module": "", "line": ""}]})
        self.assertEqual(len(db.match_fingerprint_scores(
            "Network packet too big", {"outcome": "eof"})), 1)
        self.assertEqual(db.match_fingerprint_scores(
            "Network packet too big", {"outcome": "router_error",
                                       "fields": {"release": "916"}}), [])

    def test_duplicate_rows_count_once_per_probe(self):
        db = self.database({"No route": [{"release": "916", "line": "4004",
                                           "module": "n.cpp", "patch_number": "100"},
                                          {"release": "916", "line": "4004",
                                           "module": "n.cpp", "patch_number": "100"}]})
        matches = db.match_fingerprint_scores("No route", {"outcome": "router_error",
            "fields": {"release": "916", "line": "4004", "module": "n.cpp"}})
        self.assertEqual(fingerprint.ranked_versions({"No route": matches})[0]
                         ["scores"], {"No route": 1.0})

    def test_control_reply_is_not_misclassified_as_error(self):
        connection = mock.Mock()
        connection.sr.return_value = SAPNI() / SAPRouter(
            type=SAPRouter.SAPROUTER_CONTROL, version=40, opcode=2)
        with mock.patch.object(fingerprint.SAPNIStreamSocket, "get_nisocket",
                               return_value=connection) as factory:
            result = fingerprint.probe_packet("127.0.0.1", 3299,
                                              SAPRouter(), 2.0)
        self.assertEqual(result["outcome"], "router_reply")
        self.assertEqual(factory.call_args.kwargs["max_frame_length"], 1 << 20)
        self.assertEqual(factory.call_args.kwargs["timeout"], 2.0)
        connection.close.assert_called_once()

    def test_eof_and_observation_export(self):
        connection = mock.Mock()
        connection.sr.side_effect = OSError(
            (100, "Underlying stream socket tore down with 4 bytes pending"))
        with mock.patch.object(fingerprint.SAPNIStreamSocket, "get_nisocket",
                               return_value=connection):
            result = fingerprint.probe_packet("127.0.0.1", 3299,
                                              SAPRouter(), 2.0)
        self.assertEqual(result, {"outcome": "eof"})
        self.assertEqual(fingerprint.export_observations({
            "No route": {"outcome": "router_error",
                         "fields": {"line": "observed"}},
            "Network packet too big": result,
            "Invalid control opcode": {"outcome": "router_reply",
                                       "fields": {"version": 40}}}),
            {"No route": [{"line": "observed"}],
             "Network packet too big": [{"outcome": "eof"}],
             "Invalid control opcode": [{"outcome": "router_reply",
                                         "version": 40}]})

    def test_official_database_has_new_probes_and_eof_records(self):
        path = Path(fingerprint.__file__).with_name("router_fingerprints.json")
        db = fingerprint.FingerprintDB(str(path))
        for name in ("Route bad entries", "Route bad rest"):
            self.assertTrue(db.fingerprints_db[name])
        eof_rows = [row for row in db.fingerprints_db["Network packet too big"]
                    if row.get("outcome") == "eof"]
        self.assertEqual({row.get("release") for row in eof_rows},
                         {"753", "793", "916"})
        self.assertTrue(all(row.get("version") == "40" for row in eof_rows))


if __name__ == "__main__":
    unittest.main()
