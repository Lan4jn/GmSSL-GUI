#!/usr/bin/env python3
"""Client for interacting with GmSSL engine-service internal API."""
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]


def load_engine_token():
    token = os.environ.get("GMSSL_ENGINE_TOKEN")
    if token:
        return token
    env_file = ROOT / ".env.local"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("GMSSL_ENGINE_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise RuntimeError("GMSSL_ENGINE_TOKEN not found in environment or .env.local")


class EngineClient:
    _global_trace = []
    _max_global_trace = 5000

    def __init__(self, base_url="http://127.0.0.1:8081", enable_trace=True, max_trace_entries=1000):
        self.base_url = base_url.rstrip("/") + "/internal/v1"
        self.token = load_engine_token()
        self.enable_trace = enable_trace
        self.max_trace_entries = max_trace_entries
        self.trace = []

    def get_capabilities(self):
        req = urllib.request.Request(
            f"{self.base_url}/capabilities",
            headers={"X-Engine-Token": self.token},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())

    def execute(self, tool_id, parameters=None, inputs=None, stdin=None, timeout_seconds=30):
        parameters = parameters or {}
        formatted_inputs = {}
        if inputs:
            for k, v in inputs.items():
                if isinstance(v, dict):
                    formatted_inputs[k] = v
                elif isinstance(v, bytes):
                    formatted_inputs[k] = {
                        "name": f"{k}.bin",
                        "contentBase64": base64.b64encode(v).decode(),
                    }
                elif isinstance(v, str):
                    formatted_inputs[k] = {
                        "name": f"{k}.txt",
                        "contentBase64": base64.b64encode(v.encode()).decode(),
                    }

        stdin_b64 = None
        if stdin is not None:
            if isinstance(stdin, str):
                stdin_b64 = base64.b64encode(stdin.encode()).decode()
            elif isinstance(stdin, bytes):
                stdin_b64 = base64.b64encode(stdin).decode()

        payload = {
            "id": str(uuid.uuid4()),
            "toolId": tool_id,
            "parameters": parameters,
            "inputs": formatted_inputs,
            "stdinBase64": stdin_b64,
            "timeoutSeconds": timeout_seconds,
        }

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self.base_url}/executions",
            data=data,
            headers={
                "Content-Type": "application/json",
                "X-Engine-Token": self.token,
            },
            method="POST",
        )
        result = None
        raw_resp = b""
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds + 10) as resp:
                raw_resp = resp.read()
                result = json.loads(raw_resp.decode())
        except urllib.error.HTTPError as e:
            raw_resp = e.read()
            err_body = raw_resp.decode(errors="replace")
            try:
                parsed = json.loads(err_body)
                result = {"http_code": e.code, "error": parsed}
            except Exception:
                result = {"http_code": e.code, "error_raw": err_body}

        if self.enable_trace:
            self._record_trace(tool_id, parameters, result, raw_resp)

        return result

    def _record_trace(self, tool_id, parameters, result, raw_resp):
        if len(self.trace) >= self.max_trace_entries:
            return

        op = "execute"
        if "stage" in parameters:
            op = f"stage_{parameters['stage']}"
        elif parameters.get("encrypt") is True:
            op = "encrypt"
        elif parameters.get("decrypt") is True:
            op = "decrypt"
        elif "alg" in parameters:
            op = f"alg_{parameters['alg']}"

        status = result.get("status")
        if not status and "http_code" in result:
            status = f"HTTP_{result['http_code']}"
        elif not status:
            status = "UNKNOWN"

        resp_hash = hashlib.sha256(raw_resp if raw_resp else json.dumps(result, sort_keys=True).encode()).hexdigest()

        entry = {
            "toolId": tool_id,
            "operation": op,
            "status": status,
            "exitCode": result.get("exitCode"),
            "responseHash": resp_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.trace.append(entry)
        if len(EngineClient._global_trace) < EngineClient._max_global_trace:
            EngineClient._global_trace.append(entry)

    def get_trace(self):
        return list(self.trace)

    def clear_trace(self):
        self.trace.clear()

    def get_observed_tools(self, successful_only=True):
        tools = set()
        for entry in self.trace:
            if successful_only:
                if entry.get("status") == "SUCCEEDED" or entry.get("exitCode") == 0:
                    tools.add(entry["toolId"])
            else:
                tools.add(entry["toolId"])
        return sorted(tools)

    @classmethod
    def get_global_trace(cls):
        return list(cls._global_trace)

    @classmethod
    def clear_global_trace(cls):
        cls._global_trace.clear()

    @classmethod
    def get_global_observed_tools(cls, successful_only=True):
        tools = set()
        for entry in cls._global_trace:
            if successful_only:
                if entry.get("status") == "SUCCEEDED" or entry.get("exitCode") == 0:
                    tools.add(entry["toolId"])
            else:
                tools.add(entry["toolId"])
        return sorted(tools)

    @staticmethod
    def get_artifact(resp, name):
        for art in resp.get("artifacts", []):
            if art["name"] == name:
                return base64.b64decode(art["contentBase64"])
        return None

    @staticmethod
    def get_stdout_bytes(resp):
        out = resp.get("stdoutBase64")
        return base64.b64decode(out) if out else b""

    @staticmethod
    def get_stdout_text(resp):
        return EngineClient.get_stdout_bytes(resp).decode(errors="replace")

    @staticmethod
    def get_updated_input(resp, token):
        for item in resp.get("updatedInputs", []):
            if item.get("token") == token:
                return base64.b64decode(item["contentBase64"])
        return None
