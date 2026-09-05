"""Offline regression tests: python3 -m unittest discover -s tests -v."""

import json
import os
from pathlib import Path
import signal
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

print('"FROM: 192.0.2.1#123 Example Inc (Berlin, DE)"')
print('"PROTO: ' + ("UDP" if number % 2 else "TCP") + '"')
print('"ECS: 0.0.0.0/0"')
'''


class ParserTests(unittest.TestCase):
    def test_response_formats(self):
        script = SCRIPT.read_text()
        parser = script.split("parse_response() {", 1)[1].split(
            "enrich_unknown_organizations() {", 1
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
        ]
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
