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
