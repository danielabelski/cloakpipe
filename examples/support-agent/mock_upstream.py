#!/usr/bin/env python3
"""A stand-in MCP server for the support-agent example.

Speaks newline-delimited JSON-RPC on stdin/stdout, like a stdio MCP server:
answers initialize, tools/list and tools/call. Every tools/call it receives
is logged to stderr as `upstream received: <tool> <arguments>`, so you can
see which calls got past the gate. Set MOCK_UPSTREAM_LOG to a file path to
also append each received call there as one JSON line.
"""
import json
import os
import sys

TOOLS = [
    {"name": "lookup_ticket", "inputSchema": {"type": "object", "properties": {"ticket_id": {"type": "string"}}}},
    {"name": "send_email", "inputSchema": {"type": "object", "properties": {
        "to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}}}},
    {"name": "export_customers", "inputSchema": {"type": "object"}},
]


def reply(msg_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    msg_id = msg.get("id")
    method = msg.get("method")
    if msg_id is None:
        continue  # a notification: no reply
    if method == "initialize":
        reply(msg_id, {
            "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mock-support-tools", "version": "0"},
        })
    elif method == "tools/list":
        reply(msg_id, {"tools": TOOLS})
    elif method == "tools/call":
        params = msg.get("params", {})
        name, arguments = params.get("name"), params.get("arguments", {})
        sys.stderr.write("upstream received: %s %s\n" % (name, json.dumps(arguments, sort_keys=True)))
        sys.stderr.flush()
        if os.environ.get("MOCK_UPSTREAM_LOG"):
            with open(os.environ["MOCK_UPSTREAM_LOG"], "a") as log:
                log.write(json.dumps({"name": name, "arguments": arguments}, sort_keys=True) + "\n")
        reply(msg_id, {"content": [{"type": "text", "text": "%s: done" % name}]})
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id,
                                     "error": {"code": -32601, "message": "method not found"}}) + "\n")
        sys.stdout.flush()
