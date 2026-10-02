"""Offline regression tests: python3 -m unittest discover -s tests -v."""

import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "dnsleaktest.sh"
MOCK_DIG = r'''
import fcntl
import json
import os
from pathlib import Path
import time

state = Path(os.environ["MOCK_STATE"])
with state.open("r+") as handle:
    fcntl.flock(handle, fcntl.LOCK_EX)
    data = json.load(handle)
    data["active"] += 1
    data["started"] += 1
    number = data["started"]
    data["peak"] = max(data["peak"], data["active"])
    data["pids"].append(os.getpid())
    handle.seek(0)
    handle.truncate()
    json.dump(data, handle)

mode = os.environ.get("MOCK_MODE", "normal")
time.sleep(30 if mode == "slow" else (0.005 if number % 3 else 0.04))
with state.open("r+") as handle:
    fcntl.flock(handle, fcntl.LOCK_EX)
    data = json.load(handle)
    data["active"] -= 1
    handle.seek(0)
    handle.truncate()
    json.dump(data, handle)

if mode == "failure":
    print("connection timed out")
    raise SystemExit(9)
if mode == "unparseable":
    print('"ID: 123"')
    raise SystemExit
if mode == "protocol_only":
    print('"FROM: 172.69.149.' + str(40 if number % 2 else 41) + '#123 ('
          + ("UDP" if number % 2 else "TCP") + ')"')
    print('"ECS: 0.0.0.0/0"')
    raise SystemExit
if mode == "misplaced_protocol":
    ip = "172.69.149.40" if number % 2 else "185.150.99.1"
    print('"resolver: ' + ip + '"')
    print('"resolverOrg: UDP"')
    print('"proto: Unknown"')
    raise SystemExit
if mode == "ipv6_protocol_only":
    print('"FROM: 2400:cb00:696:1024::ac45:'
          + ("9528" if number % 2 else "9529") + '#123 (UDP)"')
    raise SystemExit
if mode == "custom":
    print(os.environ["MOCK_RESPONSE"])
    raise SystemExit

print('"FROM: 192.0.2.1#123 Example Inc (Berlin, DE)"')
print('"PROTO: ' + ("UDP" if number % 2 else "TCP") + '"')
print('"ECS: 0.0.0.0/0"')
'''

MOCK_CURL = r'''
import fcntl
import json
import os
import sys
import time

url = sys.argv[-1]
with open(os.environ["MOCK_HTTP_LOG"], "a") as log:
    fcntl.flock(log, fcntl.LOCK_EX)
    log.write(url + "\n")
response = json.loads(os.environ.get("MOCK_HTTP", "{}")).get(url, {"_exit": 22})
if isinstance(response, dict) and "_slow" in response:
    timeout = float(sys.argv[sys.argv.index("--max-time") + 1])
    time.sleep(timeout + 0.05)
    raise SystemExit(28)
if isinstance(response, dict) and "_exit" in response:
    raise SystemExit(response["_exit"])
if response == "INVALID_JSON":
    print("{not JSON")
else:
    print(json.dumps(response))
'''


class ParserTests(unittest.TestCase):
    def test_response_formats(self):
        script = SCRIPT.read_text()
        parser = script.split("parse_response() {", 1)[1].split(
            "enrich_missing_metadata() {", 1
        )[0]
        command = "parse_response() {" + parser + "\nparse_response\n"
        cases = [
            ('"EDNS: version: 0; flags: do; udp: 1232"\n'
             '"FROM: 62.133.35.16#39708 (xTom GmbH) '
             '(Dusseldorf, North Rhine-Westphalia, DE) (UDP)"',
             ["62.133.35.16", "xTom GmbH",
              "Dusseldorf, North Rhine-Westphalia, DE", "UDP", "Unknown"]),
            ('"FROM: 192.0.2.1#123 Example Inc (Berlin, DE)"\n"PROTO: UDP"',
             ["192.0.2.1", "Example Inc", "Berlin, DE", "UDP", "Unknown"]),
            ('"FROM: 192.0.2.1#123 Example (Europe) Ltd (Berlin, DE)"\n'
             '"PROTO: TCP"',
             ["192.0.2.1", "Example (Europe) Ltd", "Berlin, DE", "TCP", "Unknown"]),
            ('"FROM: 192.0.2.1#123 (Example (Europe) Ltd) (Berlin, DE) (UDP)"',
             ["192.0.2.1", "Example (Europe) Ltd", "Berlin, DE", "UDP", "Unknown"]),
            ('"FROM: 2001:db8::1#123 Example (Europe) Ltd (Berlin (City), DE)"\n'
             '"PROTO: UDP"\n"ECS: 192.0.2.0/24 scope/0"',
             ["2001:db8::1", "Example (Europe) Ltd", "Berlin (City), DE",
              "UDP", "192.0.2.0/24"]),
            ('"FROM: 192.0.2.1#123 (Example (Europe) Ltd) '
             '(Berlin (City), DE) (TCP)"',
             ["192.0.2.1", "Example (Europe) Ltd", "Berlin (City), DE",
              "TCP", "Unknown"]),
            ('"resolver: 192.0.2.1"\n"resolverOrg: Example Inc"\n'
             '"resolverGeo: Berlin, DE"\n"proto: UDP"\n"clientSubnet: None"',
             ["192.0.2.1", "Example Inc", "Berlin, DE", "UDP", "None"]),
            ('"FROM: 192.0.2.1#123"',
             ["192.0.2.1", "Unknown", "Unknown", "Unknown", "Unknown"]),
            ('"FROM: 192.0.2.1#123 (Example Inc) (Berlin, DE)"\n"PROTO: TCP"',
             ["192.0.2.1", "Example Inc", "Berlin, DE", "TCP", "Unknown"]),
            ('"FROM: 192.0.2.1#123 (UDP) extra text"',
             ["192.0.2.1", "Unknown", "Unknown", "UDP", "Unknown"]),
            ('"FROM: 192.0.2.1#123 ( UDP )"',
             ["192.0.2.1", "Unknown", "Unknown", "UDP", "Unknown"]),
            ('"FROM: 192.0.2.1#123 (udp)"',
             ["192.0.2.1", "Unknown", "Unknown", "UDP", "Unknown"]),
            ('"FROM: 192.0.2.1#123 (Example Inc) (Berlin, DE) (UDP) extra text"',
             ["192.0.2.1", "Example Inc", "Berlin, DE", "UDP", "Unknown"]),
            ('"resolver: 192.0.2.1"\n"resolverOrg: UDP"\n"proto: Unknown"',
             ["192.0.2.1", "Unknown", "Unknown", "UDP", "Unknown"]),
            ('"FROM: 192.0.2.1#123 UDP"',
             ["192.0.2.1", "Unknown", "Unknown", "UDP", "Unknown"]),
            ('"FROM: 192.0.2.1#123 Example Inc (TCP)"',
             ["192.0.2.1", "Example Inc", "Unknown", "TCP", "Unknown"]),
        ]
        for endpoint in ("192.0.2.1", "2001:db8::1"):
            for protocol in ("UDP", "TCP", "TLS", "QUIC", "HTTPS"):
                for metadata, organization, geo in (
                    ("", "Unknown", "Unknown"),
                    ("(Example (Europe) Ltd) ", "Example (Europe) Ltd", "Unknown"),
                    ("(Example (Europe) Ltd) (Berlin (City), DE) ",
                     "Example (Europe) Ltd", "Berlin (City), DE"),
                ):
                    cases.append((
                        f'"FROM: {endpoint}#123 {metadata}({protocol})"\n'
                        '"ECS: 192.0.2.0/24 scope/0"',
                        [endpoint, organization, geo, protocol, "192.0.2.0/24"],
                    ))
        for response, expected in cases:
            with self.subTest(response=response):
                result = subprocess.run(
                    ["bash", "-c", command], input=response + "\n",
                    text=True, capture_output=True, timeout=5, check=True,
                )
                self.assertEqual(result.stdout.rstrip("\n").split("\t"), expected)


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        mock = self.root / "dig"
        mock.write_text("#!" + sys.executable + "\n" + MOCK_DIG)
        mock.chmod(0o755)
        self.state = self.root / "state.json"
        self.reset_state()
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"],
                        MOCK_STATE=str(self.state), TMPDIR=str(self.root), MOCK_MODE="normal")
        # Never make real HTTP requests in offline regression tests.
        mock_curl = self.root / "curl"
        mock_curl.write_text("#!" + sys.executable + "\n" + MOCK_CURL)
        mock_curl.chmod(0o755)
        self.http_log = self.root / "http.log"
        self.env["MOCK_HTTP_LOG"] = str(self.http_log)
        self.env["MOCK_HTTP"] = "{}"

    def set_http(self, responses):
        self.env["MOCK_HTTP"] = json.dumps(responses)

    def http_calls(self):
        return self.http_log.read_text().splitlines() if self.http_log.exists() else []

    def reset_state(self):
        self.state.write_text(json.dumps({"active": 0, "peak": 0, "started": 0, "pids": []}))

    def run_script(self, *args, script=SCRIPT):
        return subprocess.run(["bash", str(script), *args], env=self.env,
                              text=True, capture_output=True, timeout=20)

    def test_parallel_limit_and_complete_results(self):
        # Exercise both wait -n and the oldest-worker fallback on current Bash.
        fallback = self.root / "fallback.sh"
        fallback.write_text(SCRIPT.read_text().replace("  HAVE_WAIT_N=1", "  HAVE_WAIT_N=0"))
        for script in (SCRIPT, fallback):
            for limit in (1, 5):
                with self.subTest(script=script.name, limit=limit):
                    self.reset_state()
                    result = self.run_script("-q", "80", "-p", str(limit), script=script)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    data = json.loads(self.state.read_text())
                    self.assertLessEqual(data["peak"], limit)
                    self.assertEqual(data["started"], 80)
                    self.assertEqual(data["active"], 0)
                    self.assertIn("80/80 queries", result.stdout)

    def test_all_protocols_are_retained_once(self):
        result = self.run_script("-q", "6", "-p", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line for line in result.stdout.splitlines() if " | 192.0.2.1 | " in line]
        self.assertEqual(len(rows), 1)
        protocols = rows[0].split(" | ")[-1].split(", ")
        self.assertCountEqual(protocols, ["UDP", "TCP"])
        self.assertIn("1 resolver egress IP(s)", result.stdout)

    def test_query_errors_keep_diagnostics(self):
        for mode, expected in (("failure", "connection timed out"),
                               ("unparseable", '"ID: 123"')):
            with self.subTest(mode=mode):
                self.reset_state()
                self.env["MOCK_MODE"] = mode
                result = self.run_script("-q", "1")
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)

    def test_protocol_only_responses_report_unknown_organizations(self):
        self.env["MOCK_MODE"] = "protocol_only"
        result = self.run_script("-n", "-q", "6", "-p", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Unknown | 172.69.149.40 | Unknown | UDP", result.stdout)
        self.assertIn("Unknown | 172.69.149.41 | Unknown | TCP", result.stdout)
        self.assertIn("2 resolver egress IP(s): 0 identified organization(s), "
                      "2 resolver(s) with unknown organization.", result.stdout)
        self.assertIn("6/6 queries", result.stdout)
        self.assertIn("At least one resolver organization could not be identified.",
                      result.stdout)
        self.assertEqual(self.http_calls(), [])

    def test_protocol_only_responses_can_be_enriched(self):
        self.env["MOCK_MODE"] = "protocol_only"
        self.set_http({
            "https://dnscheck.tools/known-ipranges.json":
                [{"desc": "Cloudflare", "ranges": ["172.69.149.0/24"]}],
            "https://ip.addr.tools/172.69.149.0":
                {"city": "Munich", "region": "Bavaria", "country": "DE"},
        })
        # Automatic enrichment: the normal invocation needs no -e.
        result = self.run_script("-q", "6", "-p", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Cloudflare | 172.69.149.40 | Munich, Bavaria, DE | UDP", result.stdout)
        self.assertIn("Cloudflare | 172.69.149.41 | Munich, Bavaria, DE | TCP", result.stdout)
        self.assertIn("2 resolver egress IP(s) across 1 organization(s).", result.stdout)
        self.assertIn("Missing metadata supplemented for 2/2 resolver(s)", result.stdout)
        self.assertCountEqual(self.http_calls(), [
            "https://dnscheck.tools/known-ipranges.json",
            "https://ip.addr.tools/172.69.149.0",
        ])

    def test_transport_labels_cannot_hide_multiple_organizations(self):
        self.env["MOCK_MODE"] = "misplaced_protocol"
        self.set_http({
            "https://dnscheck.tools/known-ipranges.json": [
                {"desc": "Cloudflare", "ranges": ["172.69.149.0/24"]},
                {"desc": "Example DNS", "ranges": ["185.150.99.0/24"]},
            ],
            "https://ip.addr.tools/172.69.149.0": {"city": "Frankfurt", "country": "DE"},
            "https://ip.addr.tools/185.150.99.0": {"city": "Munich", "country": "DE"},
        })
        result = self.run_script("-q", "6", "-p", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Cloudflare | 172.69.149.40 | Frankfurt, DE | UDP", result.stdout)
        self.assertIn("Example DNS | 185.150.99.1 | Munich, DE | UDP", result.stdout)
        self.assertIn("2 resolver egress IP(s) across 2 organization(s).", result.stdout)
        self.assertIn("Multiple resolver organizations detected.", result.stdout)
        self.assertNotIn("egress IPs from one organization", result.stdout)
        self.assertNotIn(" UDP | ", result.stdout)

    def test_unidentified_providers_are_not_counted_as_one_udp_organization(self):
        self.env["MOCK_MODE"] = "misplaced_protocol"
        result = self.run_script("-n", "-q", "6", "-p", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Unknown | 172.69.149.40 | Unknown | UDP", result.stdout)
        self.assertIn("Unknown | 185.150.99.1 | Unknown | UDP", result.stdout)
        self.assertIn("0 identified organization(s), 2 resolver(s) with unknown organization",
                      result.stdout)
        self.assertNotIn("across 1 organization(s)", result.stdout)

    def test_complete_dns_metadata_does_not_make_http_requests(self):
        result = self.run_script("-q", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Example Inc | 192.0.2.1 | Berlin, DE", result.stdout)
        self.assertEqual(self.http_calls(), [])

    def test_geo_only_enrichment_preserves_dns_provider_and_ecs(self):
        self.env["MOCK_MODE"] = "custom"
        self.env["MOCK_RESPONSE"] = (
            '"FROM: 172.69.149.40#123 (Original DNS) (UDP)"\n'
            '"ECS: 192.0.2.0/24"'
        )
        self.set_http({
            "https://ip.addr.tools/172.69.149.0":
                {"city": "Munich", "region": "Bavaria", "country": "DE", "org": "Wrong DNS"},
        })
        result = self.run_script("-q", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Original DNS | 172.69.149.40 | Munich, Bavaria, DE | UDP",
                      result.stdout)
        self.assertIn("Original DNS | 172.69.149.40 | 192.0.2.0/24", result.stdout)
        self.assertEqual(self.http_calls(), ["https://ip.addr.tools/172.69.149.0"])

    def test_provider_only_enrichment_preserves_dns_geo(self):
        self.env["MOCK_MODE"] = "custom"
        self.env["MOCK_RESPONSE"] = (
            '"resolver: 172.69.149.40"\n"resolverGeo: Original City, DE"\n"proto: UDP"'
        )
        self.set_http({
            "https://dnscheck.tools/known-ipranges.json":
                [{"desc": "Cloudflare", "ranges": ["172.69.149.0/24"]}],
        })
        result = self.run_script("-e", "-q", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Cloudflare | 172.69.149.40 | Original City, DE | UDP", result.stdout)
        self.assertEqual(self.http_calls(), ["https://dnscheck.tools/known-ipranges.json"])

    def test_ipv6_geo_uses_and_caches_56_prefix(self):
        self.env["MOCK_MODE"] = "ipv6_protocol_only"
        self.set_http({
            "https://dnscheck.tools/known-ipranges.json":
                [{"desc": "Cloudflare", "ranges": ["2400:cb00::/32"]}],
            "https://ip.addr.tools/2400:cb00:696:1000::":
                {"city": "Munich", "region": "", "country": "DE"},
        })
        result = self.run_script("-q", "6", "-p", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        for suffix in ("9528", "9529"):
            self.assertIn(f"Cloudflare | 2400:cb00:696:1024::ac45:{suffix} | Munich, DE | UDP",
                          result.stdout)
        self.assertEqual(self.http_calls().count(
            "https://ip.addr.tools/2400:cb00:696:1000::"), 1)
        self.assertEqual(len(self.http_calls()), 2)

    def test_rdap_bootstrap_registrant_template_and_range_cache(self):
        self.env["MOCK_MODE"] = "protocol_only"
        rdap = {
            "startAddress": "172.69.149.0", "endAddress": "172.69.149.255",
            "entities": [
                {"roles": ["technical"], "vcardArray": ["vcard", [["fn", {}, "text", "Wrong"]]]},
                {"roles": ["registrant"], "vcardArray": ["vcard", [
                    ["fn", {}, "text", "A Person"], ["kind", {}, "text", "individual"]]]},
                {"roles": ["registrant"], "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Example LLC"], ["kind", {}, "text", "org"]]]},
            ],
        }
        responses = {
            "https://dnscheck.tools/known-ipranges.json":
                [{"desc": "DNS hosted by {}", "ranges": ["172.69.149.0/24"]}],
            "https://ip.addr.tools/172.69.149.0": {"country": "DE"},
            "https://data.iana.org/rdap/ipv4.json": {"services": [
                [["172.0.0.0/8"], ["http://insecure.invalid/", "https://rdap.example/"]],
            ]},
        }
        for ip in ("172.69.149.40", "172.69.149.41"):
            responses["https://rdap.example/ip/" + ip] = rdap
        self.set_http(responses)
        result = self.run_script("-q", "6", "-p", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DNS hosted by Example | 172.69.149.40 | DE | UDP", result.stdout)
        self.assertIn("DNS hosted by Example | 172.69.149.41 | DE | TCP", result.stdout)
        self.assertEqual(self.http_calls().count("https://data.iana.org/rdap/ipv4.json"), 1)
        self.assertEqual(sum(url.startswith("https://rdap.example/ip/")
                             for url in self.http_calls()), 1)
        self.assertFalse(any(url.startswith("http://") for url in self.http_calls()))

    def test_enrichment_failures_leave_dns_results_usable(self):
        self.env["MOCK_MODE"] = "protocol_only"
        result = self.run_script("-q", "6", "-p", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Unknown | 172.69.149.40 | Unknown | UDP", result.stdout)
        self.assertIn("Unknown | 172.69.149.41 | Unknown | TCP", result.stdout)
        self.assertIn("6/6 queries", result.stdout)
        self.assertIn("2 resolver(s) with missing fields; DNS results remain valid.",
                      result.stdout)

    def test_ipv6_rdap_fallback_when_known_ranges_are_unavailable(self):
        self.env["MOCK_MODE"] = "ipv6_protocol_only"
        rdap = {"startAddress": "2400:cb00::", "endAddress": "2400:cb00:ffff:ffff:ffff:ffff:ffff:ffff",
                "name": "Example IPv6 DNS"}
        responses = {
            "https://data.iana.org/rdap/ipv6.json": {"services": [
                [["2400:cb00::/32"], ["https://rdap.example/"]]]},
            "https://ip.addr.tools/2400:cb00:696:1000::": {"country": "DE"},
        }
        for suffix in ("9528", "9529"):
            responses["https://rdap.example/ip/2400:cb00:696:1024::ac45:" + suffix] = rdap
        self.set_http(responses)
        result = self.run_script("-q", "6", "-p", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Example IPv6 DNS | 2400:cb00:696:1024::ac45:9528 | DE | UDP",
                      result.stdout)
        self.assertEqual(sum(url.startswith("https://rdap.example/ip/")
                             for url in self.http_calls()), 1)

    def test_partial_geo_and_invalid_json_keep_provider(self):
        self.env["MOCK_MODE"] = "protocol_only"
        self.set_http({
            "https://dnscheck.tools/known-ipranges.json":
                [{"desc": "Cloudflare", "ranges": ["172.69.149.0/24"]}],
            "https://ip.addr.tools/172.69.149.0": "INVALID_JSON",
        })
        result = self.run_script("-q", "6", "-p", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Cloudflare | 172.69.149.40 | Unknown | UDP", result.stdout)
        self.assertIn("2 resolver(s) with missing fields; DNS results remain valid.",
                      result.stdout)

    def test_nonpublic_resolver_addresses_are_not_sent_to_http_services(self):
        self.env["MOCK_MODE"] = "custom"
        for address in ("192.168.1.1", "127.0.0.1", "fd00::1", "2001:db8::1"):
            with self.subTest(address=address):
                self.env["MOCK_RESPONSE"] = f'"FROM: {address}#123 (UDP)"'
                result = self.run_script("-q", "1")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"Unknown | {address} | Unknown | UDP", result.stdout)
                self.assertEqual(self.http_calls(), [])

    def test_metadata_controls_cannot_inject_extra_rows(self):
        self.env["MOCK_MODE"] = "protocol_only"
        self.set_http({
            "https://dnscheck.tools/known-ipranges.json":
                [{"desc": "Cloud\tflare\nInjected", "ranges": ["172.69.149.0/24"]}],
            "https://ip.addr.tools/172.69.149.0":
                {"city": "Munich\r", "region": 123, "country": "DE\x1b"},
        })
        result = self.run_script("-q", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Cloud flare Injected | 172.69.149.40 | Munich, DE | UDP", result.stdout)
        self.assertNotIn("\x1b", result.stdout)

    def test_enrichment_respects_shared_time_budget(self):
        self.env["MOCK_MODE"] = "protocol_only"
        self.set_http({
            "https://dnscheck.tools/known-ipranges.json": {"_slow": True},
        })
        short_budget = self.root / "short-budget.sh"
        short_budget.write_text(SCRIPT.read_text().replace("ENRICHMENT_BUDGET=30",
                                                          "ENRICHMENT_BUDGET=1"))
        start = time.monotonic()
        result = self.run_script("-q", "2", script=short_budget)
        self.assertLess(time.monotonic() - start, 2.5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2/2 queries", result.stdout)
        self.assertEqual(self.http_calls(), ["https://dnscheck.tools/known-ipranges.json"])

    def test_missing_enrichment_dependencies_fall_back_unless_explicitly_required(self):
        # Keep all DNS-test tools but hide Python/curl from command -v.
        for command in ("bash", "awk", "find", "sort", "mktemp", "mkdir", "rm"):
            (self.root / command).symlink_to(shutil.which(command))
        (self.root / "curl").rename(self.root / "disabled-curl")
        self.env["PATH"] = str(self.root)
        self.env["MOCK_MODE"] = "protocol_only"
        result = self.run_script("-q", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Metadata enrichment unavailable", result.stderr)
        self.assertIn("2/2 queries", result.stdout)
        result = self.run_script("-e", "-q", "2")
        self.assertEqual(result.returncode, 1)
        self.assertIn("required for metadata enrichment", result.stderr)
        result = self.run_script("-n", "-q", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Metadata enrichment unavailable", result.stderr)
        self.assertEqual(self.http_calls(), [])

    def test_signals_reap_dig_children_and_remove_work_directory(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=sig):
                self.reset_state()
                self.env["MOCK_MODE"] = "slow"
                with (self.root / "signal.log").open("w") as log:
                    process = subprocess.Popen(
                        ["bash", str(SCRIPT), "-q", "6", "-p", "3"],
                        env=self.env, stdout=log, stderr=log, start_new_session=True,
                    )
                    try:
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            # Writers truncate under flock; read under the same lock.
                            import fcntl
                            with self.state.open() as handle:
                                fcntl.flock(handle, fcntl.LOCK_SH)
                                data = json.load(handle)
                            if data["started"] == 3:
                                break
                            time.sleep(0.01)
                        self.assertEqual(data["started"], 3)
                        work_dirs = [path for path in self.root.iterdir() if path.is_dir()]
                        self.assertEqual(len(work_dirs), 1)
                        process.send_signal(sig)
                        self.assertEqual(process.wait(timeout=5), 128 + sig)
                        for pid in data["pids"]:
                            with self.assertRaises(ProcessLookupError, msg=f"dig {pid} survived"):
                                os.kill(pid, 0)
                        self.assertFalse(work_dirs[0].exists())
                    finally:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
