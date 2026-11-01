"""Smoke-test an implant binary against a mock OpenAEV platform.

The mock platform serves a Command payload and records the implant's
callbacks. The implant is run once per native executor of the host OS. It
must exit cleanly, report the command's output in a successful execution
callback, then complete, without logging any error.

Usage: python implant-smoke.py <path to openaev-implant binary>
"""

import base64
import json
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Each command prints EXPECTED only if the shell really evaluates it: the
# text of the command alone never contains it.
EXPECTED = "openaev-42"
COMMANDS = {
    "sh": 'echo "openaev-$((40+2))"',
    "bash": 'echo "openaev-$((40+2))"',
    "psh": 'Write-Output "openaev-$(40+2)"',
    "cmd": "set /a x=40+2 >nul & echo openaev-!x!",
}
EXECUTORS = ["psh", "cmd"] if sys.platform == "win32" else ["sh", "bash"]

# Callbacks received per inject id. The inject id is the executor name.
callbacks: dict[str, list[dict]] = {}


class MockPlatform(BaseHTTPRequestHandler):
    def do_GET(self):
        # /api/tenants/{tenant}/injects/{inject}/{agent}/executable-payload
        parts = self.path.strip("/").split("/")
        if len(parts) == 7 and parts[6] == "executable-payload":
            command = base64.b64encode(COMMANDS[parts[4]].encode()).decode()
            self.reply(
                200,
                {
                    "payload_type": "Command",
                    "command_executor": parts[4],
                    "command_content": command,
                },
            )
        else:
            self.reply(404, {})

    def do_POST(self):
        # /api/tenants/{tenant}/injects/execution/{agent}/callback/{inject}
        parts = self.path.strip("/").split("/")
        if len(parts) == 8 and parts[6] == "callback":
            length = int(self.headers.get("Content-Length", 0))
            callbacks.setdefault(parts[7], []).append(json.loads(self.rfile.read(length)))
            self.reply(200, {"inject_id": parts[7]})
        else:
            self.reply(404, {})

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def check(executor, returncode):
    received = callbacks.get(executor, [])
    print(f"--- {executor}: exit code {returncode}, callbacks:")
    for callback in received:
        print(json.dumps(callback))

    execution = next((c for c in received if c["execution_action"] == "command_execution"), None)
    if returncode != 0:
        return f"exit code {returncode}"
    if execution is None:
        return "no command_execution callback"
    if execution["execution_status"] != "SUCCESS":
        return f"command_execution status {execution['execution_status']}"
    output = json.loads(execution["execution_message"])
    if output["exit_code"] != 0 or output["stderr"]:
        return f"command failed: {output}"
    if output["stdout"].strip() != EXPECTED:
        return f"stdout is {output['stdout']!r}, expected {EXPECTED!r}"
    if received[-1]["execution_action"] != "complete" or received[-1]["execution_status"] != "INFO":
        return "no final complete callback"
    return None


def main():
    # The agent runs the implant from <agent dir>/runtimes/<name>/.
    runtime_dir = Path("agent/runtimes/smoke")
    runtime_dir.mkdir(parents=True, exist_ok=True)
    implant = runtime_dir / Path(sys.argv[1]).name
    shutil.copy(sys.argv[1], implant)
    implant.chmod(0o755)

    server = ThreadingHTTPServer(("127.0.0.1", 0), MockPlatform)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"

    failures = []
    for executor in EXECUTORS:
        result = subprocess.run(
            [
                str(implant.resolve()),
                "--uri", url,
                "--token", "smoke-test",
                "--unsecured-certificate", "false",
                "--with-proxy", "false",
                "--agent-id", "smoke-agent",
                "--inject-id", executor,
                "--tenant-id", "smoke-tenant",
            ],
            timeout=120,
        )
        error = check(executor, result.returncode)
        if error:
            failures.append(f"{executor}: {error}")

    log = runtime_dir / "openaev-implant.log"
    print(f"--- {log}")
    lines = log.read_text(errors="replace").splitlines() if log.exists() else []
    print("\n".join(lines) or "(missing)")
    if sum("Starting OpenAEV implant" in line for line in lines) != len(EXECUTORS):
        failures.append(f"expected one startup line per run in {log}")
    failures += [f"error logged: {line}" for line in lines if '"level":"ERROR"' in line]
    if not Path("agent/payloads/smoke").is_dir():
        failures.append("payload directory was not created")

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        sys.exit(1)
    print(f"Implant ran a command payload and reported {EXPECTED!r} with {', '.join(EXECUTORS)}")


if __name__ == "__main__":
    main()
