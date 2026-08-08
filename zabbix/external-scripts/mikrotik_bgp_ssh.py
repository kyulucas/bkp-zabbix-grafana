#!/usr/bin/env python3
"""
MikroTik BGP peers via SSH (RouterOS 6.x /routing bgp peer).

Uso no Zabbix Server (External check / script):
  mikrotik_bgp_ssh.py discover <host> <user> <senha> [porta]
  mikrotik_bgp_ssh.py get <host> <usuario> <senha> <peer_name> <campo> [porta]

Campos:
  state | state-code | prefix-count | uptime | remote-as | remote-address
  | established | disabled | updates-received | updates-sent

Estados MikroTik (state) e codigos (state-code), alinhados ao FSM BGP:
  0 disabled
  1 idle
  2 connect
  3 active
  4 opensent
  5 openconfirm
  6 established
"""

from __future__ import annotations

import json
import re
import sys

try:
    import paramiko
except ImportError:
    print("paramiko nao instalado: pip3 install paramiko", file=sys.stderr)
    sys.exit(2)


# Nomes como o RouterOS costuma expor em state=
STATE_CODE = {
    "disabled": 0,
    "idle": 1,
    "connect": 2,
    "active": 3,
    "opensent": 4,
    "openconfirm": 5,
    "established": 6,
}


def normalize_state(raw: str, disabled: bool, established_flag: bool) -> str:
    """Retorna o nome de estado descritivo (minusculo)."""
    s = (raw or "").strip().strip('"').lower()
    # RouterOS as vezes usa openSent / openConfirm
    s = s.replace(" ", "")
    aliases = {
        "opensent": "opensent",
        "open-sent": "opensent",
        "openconfirm": "openconfirm",
        "open-confirm": "openconfirm",
    }
    s = aliases.get(s, s)

    if disabled:
        return "disabled"
    if s in STATE_CODE and s != "disabled":
        return s
    if established_flag or s == "established":
        return "established"
    if not s or s in ("down", "unknown"):
        return "idle"
    return s


def state_to_code(state: str) -> int:
    return STATE_CODE.get(state, 1)  # desconhecido -> idle


def ssh_exec(host: str, user: str, password: str, command: str, port: int = 22) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=user,
        password=password,
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
        banner_timeout=20,
    )
    try:
        _stdin, stdout, stderr = client.exec_command(command, timeout=25)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        if err.strip() and not out.strip():
            raise RuntimeError(err.strip())
        return out
    finally:
        client.close()


def parse_peers(status_text: str) -> list[dict]:
    """Parse '/routing bgp peer print status' (RouterOS 6)."""
    peers: list[dict] = []
    blocks = re.split(r"(?m)^\s*(\d+)\s+([XE]*)\s+", status_text)
    i = 1
    while i + 2 < len(blocks):
        idx = blocks[i]
        flags = blocks[i + 1]
        body = blocks[i + 2]
        i += 3

        def field(name: str, default: str = "") -> str:
            m = re.search(rf"{re.escape(name)}=(\S+)", body)
            if not m:
                return default
            return m.group(1).strip().strip('"')

        name = field("name")
        if not name:
            continue

        disabled = "X" in flags
        established_flag = "E" in flags
        state = normalize_state(field("state", ""), disabled, established_flag)
        established = state == "established"

        peers.append(
            {
                "index": idx,
                "name": name,
                "flags": flags,
                "disabled": disabled,
                "established": established,
                "state": state,
                "state_code": state_to_code(state),
                "remote_address": field("remote-address"),
                "remote_as": field("remote-as"),
                "prefix_count": field("prefix-count", "0"),
                "uptime": field("uptime", "0"),
                "remote_id": field("remote-id"),
                "local_address": field("local-address"),
                "updates_received": field("updates-received", "0"),
                "updates_sent": field("updates-sent", "0"),
            }
        )
    return peers


def cmd_discover(host: str, user: str, password: str, port: int) -> None:
    raw = ssh_exec(host, user, password, "/routing bgp peer print status", port)
    peers = parse_peers(raw)
    data = []
    for p in peers:
        data.append(
            {
                "{#PEER.NAME}": p["name"],
                "{#PEER.REMOTE.AS}": p["remote_as"],
                "{#PEER.REMOTE.ADDR}": p["remote_address"],
                "{#PEER.DISABLED}": "1" if p["disabled"] else "0",
            }
        )
    print(json.dumps({"data": data}, ensure_ascii=False))


def cmd_get(host: str, user: str, password: str, peer_name: str, field: str, port: int) -> None:
    raw = ssh_exec(host, user, password, "/routing bgp peer print status", port)
    peers = parse_peers(raw)
    peer = next((p for p in peers if p["name"] == peer_name), None)
    if peer is None:
        print("NOTFOUND")
        sys.exit(1)

    key = field.strip().lower().replace("-", "_")
    mapping = {
        "state": peer["state"],
        "state_code": str(peer["state_code"]),
        "prefix_count": peer["prefix_count"],
        "uptime": peer["uptime"],
        "remote_as": peer["remote_as"],
        "remote_address": peer["remote_address"],
        "established": "1" if peer["established"] else "0",
        "disabled": "1" if peer["disabled"] else "0",
        "updates_received": peer["updates_received"],
        "updates_sent": peer["updates_sent"],
    }
    if key not in mapping:
        print(f"UNKNOWN_FIELD:{field}", file=sys.stderr)
        sys.exit(1)
    print(mapping[key])


def usage() -> None:
    print(__doc__.strip(), file=sys.stderr)
    sys.exit(2)


def main() -> None:
    if len(sys.argv) < 2:
        usage()
    action = sys.argv[1].lower()

    if action == "discover":
        if len(sys.argv) < 5:
            usage()
        host, user, password = sys.argv[2], sys.argv[3], sys.argv[4]
        port = int(sys.argv[5]) if len(sys.argv) > 5 else 22
        cmd_discover(host, user, password, port)
    elif action == "get":
        if len(sys.argv) < 7:
            usage()
        host, user, password, peer, field = sys.argv[2:7]
        port = int(sys.argv[7]) if len(sys.argv) > 7 else 22
        cmd_get(host, user, password, peer, field, port)
    else:
        usage()


if __name__ == "__main__":
    main()
