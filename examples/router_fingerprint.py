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
import json
import logging
import socket
from argparse import ArgumentParser
from pathlib import Path
# External imports
from scapy.config import conf
from scapy.packet import bind_layers, Raw
# Custom imports
import pysap
from pysap.SAPNI import SAPNIStreamSocket, SAPNI
from pysap.SAPRouter import SAPRouter, SAPRouterError, SAPRouterRouteHop


# Bind the SAPRouter layer
bind_layers(SAPNI, SAPRouter, )

# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():

    description = "This example script connects with a SAP Router service and tries to determine its version. " \
                  "Finger printing is performed by triggering different errors and looking at the lines where the " \
                  "error is produced."

    usage = "%(prog)s -d <remote host> [options]"

    parser = ArgumentParser(usage=usage, description=description, epilog=pysap.epilog)

    target = parser.add_argument_group("Target")
    target.add_argument("-d", "--remote-host", dest="remote_host", default="127.0.0.1",
                        help="Remote host [%(default)s]")
    target.add_argument("-p", "--remote-port", dest="remote_port", type=int, default=3299,
                        help="Remote port [%(default)d]")

    database = parser.add_argument_group("Database options")
    database.add_argument("-f", "--fingerprints-file", dest="fingerprints", metavar="FILE",
                          default=str(Path(__file__).with_name("router_fingerprints.json")),
                          help="Fingerprints file to use [%(default)s]")
    database.add_argument("-a", "--add-fingerprint", dest="add_fingerprint", action="store_true",
                          help="New fingerprint to add to the database in json format")
    database.add_argument("-i", "--version-information", dest="version_info",
                          help="Version information to use when adding new entries in json format")
    database.add_argument("-n", "--new-entries", dest="new_entries", action="store_true",
                          help="Generate new database entries even when the fingerprints matched")
    database.add_argument("--new-fingerprints-file", dest="new_fingerprint_file", metavar="FILE",
                          default="saprouter_new_fingerprints.json", help="File to write or load from new fingerprints")
    database.add_argument("--list-versions", dest="list_versions", action="store_true",
                          help="List version candidates represented in the database and exit")

    misc = parser.add_argument_group("Misc options")
    misc.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")
    misc.add_argument("--timeout", dest="timeout", type=float, default=7.0,
                      help="Connection and response timeout in seconds [%(default)s]")

    options = parser.parse_args()

    if not options.remote_host:
        parser.error("Remote host is required")
    if options.timeout <= 0:
        parser.error("Timeout must be positive")

    return options


def malformed_route_probe(entries, rest_nodes):
    """Build a two-hop, metadata-invalid route without forwarding a target."""
    hops = [SAPRouterRouteHop(hostname="127.0.0.1", port="3299"),
            SAPRouterRouteHop(hostname="127.0.0.1", port="3201")]
    lengths = [len(hop) for hop in hops]
    return SAPRouter(type=SAPRouter.SAPROUTER_ROUTE, route_entries=entries,
                     route_rest_nodes=rest_nodes, route_length=sum(lengths),
                     route_offset=lengths[0], route_string=hops)


# This is the list of target packets that we use during the fingerprinting. Basically it consist of a dict with the
# key being the name of the target packet and the value the construction of it.
fingerprint_targets = {
    # Connect to the SAP Route but not send any packet to trigger a timeout
    "Timeout": None,
    # Send a large packet
    "Network packet too big": Raw(b"X" * 10025),
    # Use an invalid opcode
    "Invalid control opcode": SAPRouter(type=SAPRouter.SAPROUTER_CONTROL, version=38, opcode=3),
    # Do not send a route
    "No route": SAPRouter(type=SAPRouter.SAPROUTER_ROUTE),
    # Set one entry but do no provide a route
    "No route one entry": SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                                    route_entries=1),
    # Set one entry with an invalid length but do no provide it
    "No route invalid length": SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                                         route_entries=2,
                                         route_rest_nodes=1,
                                         route_length=1,
                                         route_offset=3),
    # Set one entry with an invalid route
    "Empty route invalid length": SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                                            route_entries=2,
                                            route_rest_nodes=1,
                                            route_length=1,
                                            route_offset=0,
                                            route_string=[SAPRouterRouteHop()]),
    # Set an empty route with valid length
    "Empty route valid length": SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                                          route_entries=2,
                                          route_rest_nodes=1,
                                          route_length=6,
                                          route_offset=3,
                                          route_string=[SAPRouterRouteHop(), SAPRouterRouteHop()]),
    # Set an empty route with a null offset
    "Empty route null offset": SAPRouter(type=SAPRouter.SAPROUTER_ROUTE, route_entries=2,
                                         route_rest_nodes=1,
                                         route_length=6,
                                         route_offset=0,
                                         route_string=[SAPRouterRouteHop(), SAPRouterRouteHop()]),
    # Set an empty route with an invalid offset
    "Empty route invalid offset": SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                                            route_entries=2,
                                            route_rest_nodes=1,
                                            route_length=6,
                                            route_offset=6,
                                            route_string=[SAPRouterRouteHop(), SAPRouterRouteHop()]),
    # Set a route for a non existent domain
    "Non existent domain": SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                                     route_entries=2,
                                     route_rest_nodes=1,
                                     route_length=38,
                                     route_offset=19,
                                     route_string=[SAPRouterRouteHop(hostname="non.existent.dom"),
                                                   SAPRouterRouteHop(hostname="non.existent.dom")]),
    # Valid route for an non existent domain with an old version
    "Non existent domain old version": SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                                                 route_ni_version=0,
                                                 route_entries=2,
                                                 route_rest_nodes=1,
                                                 route_length=38,
                                                 route_offset=19,
                                                 route_string=[SAPRouterRouteHop(hostname="non.existent.dom"),
                                                               SAPRouterRouteHop(hostname="non.existent.dom")]),
    # Valid route for a valid domain but an invalid service name
    "Valid domain invalid service": SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                                              route_entries=2,
                                              route_rest_nodes=1,
                                              route_length=56,
                                              route_offset=28,
                                              route_string=[SAPRouterRouteHop(hostname="www.coresecurity.com",
                                                                              port="someservice"),
                                                            SAPRouterRouteHop(hostname="www.coresecurity.com",
                                                                              port="someservice")]),
    # Additional deterministic route-validation branches. They are useful
    # alternatives to DNS-dependent cases, not guaranteed patch separators.
    "Route bad entries": malformed_route_probe(1, 1),
    "Route bad rest": malformed_route_probe(2, 2),
}


class FingerprintDB(object):

    FINGERPRINT_FIELDS = (
        "error", "return_code", "component", "release", "version", "module",
        "line", "errorno", "errorno_text", "system_call", "detail")
    FINGERPRINT_FIELD_WEIGHTS = {
        "release": 4, "module": 4, "line": 5, "return_code": 3,
        "detail": 2, "error": 2, "version": 2}
    FINGERPRINT_MIN_SCORE = 0.55
    VERSION_INFO_FIELDS = (
        "version", "release", "patch_number", "source_id", "update_level",
        "file_version", "platform", "submitted_by", "comment")
    VERSION_IDENTITY_FIELDS = (
        "version", "release", "patch_number", "platform", "file_version")
    # Runtime rankings intentionally combine file builds of the same release.
    RANKING_IDENTITY_FIELDS = (
        "version", "release", "patch_number", "platform")

    def __init__(self, fingerprints_file):
        self.fingerprints_db = {}
        self.fingerprints_file = fingerprints_file
        self.load_fingerprints(fingerprints_file)

    def load_fingerprints(self, fingerprints_file):
        with open(fingerprints_file, 'r') as f:
            fingerprints = json.load(f)

        for target in fingerprint_targets:
            if target in fingerprints:
                self.fingerprints_db[target] = fingerprints[target]

    def add_fingerprint(self, new_fingerprint, version_info):
        with open(new_fingerprint, 'r') as f:
            new_fingerprint = json.load(f)
        if version_info:
            version_info = json.loads(version_info)
        else:
            version_info = {}

        for target in fingerprint_targets:
            if target in new_fingerprint:
                if target not in self.fingerprints_db:
                    self.fingerprints_db[target] = []
                for entry in new_fingerprint[target]:
                    record = dict(entry)
                    record.update(version_info)
                    if record not in self.fingerprints_db[target]:
                        logging.info("[*]\tAdded a new entry for the target %s" % target)
                        self.fingerprints_db[target].append(record)

        with open(self.fingerprints_file, 'w') as f:
            json.dump(self.fingerprints_db, f, sort_keys=True, indent=4, separators=(',', ': '))

    def match_fingerprint_scores(self, target, observation):
        """Return partial matches with scores, ignoring metadata and blanks."""
        matches = []
        if not isinstance(observation, dict):
            observation = {"outcome": "router_error", "fields": {
                key: decoded_value(getattr(observation, key))
                for key in self.FINGERPRINT_FIELDS
                if hasattr(observation, key)}}
        for finger in self.fingerprints_db.get(target, []):
            expected_outcome = finger.get("outcome", "router_error")
            if expected_outcome != observation.get("outcome"):
                continue
            if expected_outcome != "router_error":
                matches.append((finger, 1.0))
                continue
            fields = observation.get("fields", {})
            total = 0
            matched = 0
            discriminating = False
            for key in self.FINGERPRINT_FIELDS:
                value = finger.get(key)
                if value in (None, ""):
                    continue
                if key in ("module", "line", "return_code", "error", "detail"):
                    discriminating = True
                weight = self.FINGERPRINT_FIELD_WEIGHTS.get(key, 1)
                total += weight
                if fields.get(key) == value:
                    matched += weight
                else:
                    logging.debug("[ ]\tUnmatched %s: %r vs %r", key,
                                  value, fields.get(key))
            score = matched / total if total and discriminating else 0.0
            if score >= self.FINGERPRINT_MIN_SCORE:
                matches.append((finger, score))
        return matches

    def match_fingerprint(self, target, observation):
        """Compatibility wrapper returning the matched database records."""
        matches = self.match_fingerprint_scores(target, observation)
        return [finger for finger, _ in matches]

    def version_summary(self):
        """Return version candidates and the probes represented for each."""
        versions = {}
        for target, fingerprints in self.fingerprints_db.items():
            for fingerprint in fingerprints:
                identity = tuple(fingerprint.get(field, "")
                                 for field in self.VERSION_IDENTITY_FIELDS)
                if not any(identity):
                    continue
                versions.setdefault(identity, set()).add(target)
        return sorted(versions.items())

    @classmethod
    def rank_versions(cls, match_scores):
        """Use each probe's best score once per version."""
        versions = {}
        for target, matches in match_scores.items():
            for finger, score in matches:
                identity = tuple(
                    finger.get(field, "")
                    for field in cls.RANKING_IDENTITY_FIELDS)
                candidate = versions.setdefault(identity, {
                    "entry": finger, "scores": {}})
                best_score = candidate["scores"].get(target, 0)
                if score >= best_score:
                    candidate["entry"] = finger
                    candidate["scores"][target] = score
        return sorted(versions.values(),
                      key=lambda item: (sum(item["scores"].values()),
                                        len(item["scores"])), reverse=True)


def format_version_summary(candidates, total_probes):
    """Format the database's static version candidates as a plain-text table."""
    headings = ("NI", "Release", "Patch", "Platform", "File version", "Probes")
    rows = []
    for identity, probes in candidates:
        values = list(identity) + ["%d/%d" % (len(probes), total_probes)]
        rows.append(tuple(value if value not in (None, "") else "-"
                          for value in values))
    widths = [len(heading) for heading in headings]
    for row in rows:
        widths = [max(width, len(str(value)))
                  for width, value in zip(widths, row)]
    template = "  ".join("{:<%d}" % width for width in widths)
    separator = "  ".join("-" * width for width in widths)
    lines = [template.format(*headings), separator]
    lines.extend(template.format(*row) for row in rows)
    return "\n".join(line.rstrip() for line in lines)


def decoded_value(value):
    if isinstance(value, bytes):
        return value.decode("latin-1", errors="replace")
    return value


def probe_packet(host, port, packet, timeout):
    """Probe one target using bounded NI framing and classify its outcome."""
    conn = None
    try:
        conn = SAPNIStreamSocket.get_nisocket(
            host, port, connect_timeout=timeout, timeout=timeout,
            max_frame_length=1 << 20, keep_alive=False)
        reply = conn.recv() if packet is None else conn.sr(packet)
        router = reply.getlayer(SAPRouter)
        if router is None:
            return {"outcome": "other_reply", "fields": {}}
        if (router.opcode == 0 and router.err_text_length and
                SAPRouterError in router):
            text = router[SAPRouterError]
            return {"outcome": "router_error", "fields": {
                key: decoded_value(getattr(text, key))
                for key in FingerprintDB.FINGERPRINT_FIELDS}}
        return {"outcome": "router_reply", "fields": {
            "version": decoded_value(router.version),
            "return_code": decoded_value(router.return_code)}}
    except (socket.timeout, TimeoutError) as exc:
        return {"outcome": "probe_timeout", "message": str(exc)}
    except EOFError:
        return {"outcome": "eof"}
    except OSError as exc:
        if exc.args and isinstance(exc.args[0], tuple) and exc.args[0][0] == 100:
            return {"outcome": "eof"}
        return {"outcome": "probe_error", "message": str(exc)}
    except Exception as exc:
        return {"outcome": "probe_error", "message": "%s: %s" %
                (type(exc).__name__, exc)}
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                logging.debug("Could not close probe socket", exc_info=True)


def export_observations(observations, targets=None):
    """Export actual probe results, never copied database match records."""
    exported = {}
    for target, observation in observations.items():
        if targets is not None and target not in targets:
            continue
        if observation["outcome"] == "router_error":
            exported[target] = [dict(observation["fields"])]
        elif observation["outcome"] in ("eof", "router_reply", "other_reply"):
            exported[target] = [dict(observation.get("fields", {}),
                                     outcome=observation["outcome"])]
    return exported


# Main function
def main():
    options = parse_options()
    export_all = options.new_entries

    level = logging.INFO
    if options.verbose:
        level = logging.DEBUG
    logging.basicConfig(level=level, format='%(message)s')

    logging.info("[*] Loading fingerprint database")
    fingerprint_db = FingerprintDB(options.fingerprints)

    if options.list_versions:
        candidates = fingerprint_db.version_summary()
        logging.info("[*] Version candidates represented in %s (%d):",
                     options.fingerprints, len(candidates))
        table = format_version_summary(candidates, len(fingerprint_targets))
        logging.info("%s", table)
        return

    # Check if we were asked to add a new fingerprint
    if options.add_fingerprint:
        if not options.version_info:
            logging.info("[-] You must provide version info to add new entries to the fingerprint database !")
            return
        logging.info("[*] Adding a new entry to the fingerprint database")
        fingerprint_db.add_fingerprint(options.new_fingerprint_file, options.version_info)
        return

    misses = []
    observations = {}
    match_scores = {}
    logging.info("[*] Trying to fingerprint version using %d packets" % (len(fingerprint_targets)))

    # Trigger some errors and check with fingerprint db
    l = len(fingerprint_targets)
    i = 1
    for (target, packet) in list(fingerprint_targets.items()):

        logging.info("[*] (%d/%d) Fingerprint for packet '%s'" % (i, l, target))

        observation = probe_packet(options.remote_host, options.remote_port,
                                   packet, options.timeout)
        observations[target] = observation
        matched = fingerprint_db.match_fingerprint_scores(target, observation)

        if matched:
            best = max(score for _, score in matched)
            logging.info("[*] (%d/%d) '%s': %s, best match %.0f%%",
                         i, l, target, observation["outcome"], best * 100)
            match_scores[target] = matched
        else:
            logging.info("[*] (%d/%d) '%s': %s, no match",
                         i, l, target, observation["outcome"])
            misses.append(target)

        i += 1

    if match_scores:
        logging.info("\n[*] Supported probes (%d/%d):", len(match_scores), l)
        for target in match_scores:
            logging.info("[+] Request: %s", target)

        versions = fingerprint_db.rank_versions(match_scores)
        logging.info("\n[*] Probable versions (%d):", len(versions))
        for candidate in versions:
            version = candidate["entry"]
            msg = " ".join("%s: \"%s\"" % (field, version[field])
                           for field in FingerprintDB.VERSION_INFO_FIELDS
                           if version.get(field, "") != "")
            logging.info("[*]\tProbes: %d Score: %.2f/%d Version: %s",
                         len(candidate["scores"]),
                         sum(candidate["scores"].values()), l, msg)

    if misses:
        logging.info("\n[*] Non matched fingerprints (%d/%d):" % (len(misses), l))
        for target in misses:
            logging.info("[-] Request: %s" % target)

        logging.info("\n[-] Some error values were not found in the fingerprint database. "
                     "If you want to contribute, submit an issue to "
                     "https://github.com/OWASP/pysap/issues with the following information along "
                     "with the SAP Router file information and how it was configured.\n")
        options.new_entries = True

    # Build new entries for the fingerprint database
    if options.new_entries:
        new_fingerprint = export_observations(
            observations, None if export_all else set(misses))

        logging.info("\nNew fingerprint saved to: %s" % options.new_fingerprint_file)
        with open(options.new_fingerprint_file, 'w') as f:
            json.dump(new_fingerprint, f)

        version_info = {"patch_number": "",
                        "source_id": "",
                        "update_level": "",
                        "file_version": "",
                        "platform": "",
                        "submitted_by": "",
                        "comment": "",
                        }
        logging.info("\n\nVersion information to complete and submit:")
        logging.info("%s" % json.dumps(version_info, indent=4))


if __name__ == "__main__":
    main()
