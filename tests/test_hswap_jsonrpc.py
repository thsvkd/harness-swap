"""The stdio JSON-RPC client used to ask a harness about its own usage."""

from __future__ import annotations

import os
import sys

import pytest

from harness_swap.infrastructure import jsonrpc

SERVER = r"""
import json, sys, time
for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("method") == "initialize":
        print("starting up (log noise on stdout)", flush=True)
        print(json.dumps({"method": "note", "params": {}}), flush=True)
        print(json.dumps({"id": msg["id"], "result": {"tag": msg.get("jsonrpc")}}), flush=True)
    elif msg.get("method") == "fail":
        print(json.dumps({"id": msg["id"], "error": {"code": -32000, "message": "Authentication required",
                          "data": "token sk-ant-SECRETSECRET0123456789abcdEF rejected"}}), flush=True)
    elif msg.get("method") == "hang":
        time.sleep(30)
    elif msg.get("method") == "quit":
        sys.exit(0)
"""


@pytest.fixture
def server(tmp_path):
    path = tmp_path / "server.py"
    path.write_text(SERVER)
    return [sys.executable, str(path)]


def test_requests_skip_noise_and_notifications(server):
    with jsonrpc.session(server, dict(os.environ), timeout=10) as rpc:
        assert rpc.request("initialize", {}) == {"tag": "2.0"}
    with jsonrpc.session(server, dict(os.environ), timeout=10, version_tag=False) as rpc:
        assert rpc.request("initialize") == {"tag": None}


def test_errors_are_raised_without_credentials(server):
    with jsonrpc.session(server, dict(os.environ), timeout=10) as rpc, pytest.raises(jsonrpc.RpcError) as exc:
        rpc.request("fail")
    assert exc.value.code == -32000 and "SECRETSECRET" not in str(exc.value)


def test_deadline_exit_and_missing_binary(server):
    with jsonrpc.session(server, dict(os.environ), timeout=0.5) as rpc, pytest.raises(jsonrpc.RpcError, match="in time"):
        rpc.request("hang")
    with jsonrpc.session(server, dict(os.environ), timeout=10) as rpc, pytest.raises(jsonrpc.RpcError, match="exited"):
        rpc.request("quit")
    with pytest.raises(jsonrpc.RpcError, match="could not start"), jsonrpc.session(["/nonexistent/harness"], {}, timeout=1):
        pass


@pytest.mark.skipif(os.name != "posix", reason="process groups")
def test_helpers_started_by_the_harness_are_stopped(tmp_path):
    marker = tmp_path / "helper.pid"
    server = tmp_path / "server.py"
    server.write_text(
        "import json, subprocess, sys, time\n"
        f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(marker)!r}, 'w').write(str(p.pid))\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        "    print(json.dumps({'id': msg['id'], 'result': 1}), flush=True)\n"
    )
    with jsonrpc.session([sys.executable, str(server)], dict(os.environ), timeout=10) as rpc:
        assert rpc.request("ping") == 1
    pid = int(marker.read_text())
    import time

    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(pid, 9)
        pytest.fail("the harness's helper outlived the session")
