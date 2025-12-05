#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
import requests

OID_AS = ".1.3.6.1.4.1.2011.5.25.177.1.1.2.1.2"      # ASN
OID_REMOTE = ".1.3.6.1.4.1.2011.5.25.177.1.1.2.1.4"  # Remote address (IPv4/IPv6)
OID_STATUS = ".1.3.6.1.4.1.2011.5.25.177.1.1.2.1.5"  # STATUS

RE_LINE = re.compile(r"^\s*([0-9\.\-]+)\s*=\s*([^:]+:\s*)?(.*)$")

def run_snmpwalk(host, community, port, oid, timeout=5):
    """
    Executa snmpwalk e retorna dict {index: value}.
    Usa -On para termos OIDs numéricos e podermos extrair o índice.
    """
    cmd = [
        "snmpwalk", "-v2c", "-c", community, "-On",
        "-t", str(timeout), "-r", "1",
        f"{host}:{port}", oid
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"snmpwalk falhou ({oid}): {e.output.strip()}") from e
    except FileNotFoundError:
        raise RuntimeError("snmpwalk não encontrado no PATH")

    result = {}
    for raw in out.splitlines():
        m = RE_LINE.match(raw)
        if not m:
            continue
        full_oid, _typ, value = m.groups()
        value = value.strip().strip('"')
        if full_oid.startswith(oid + "."):
            index = full_oid[len(oid) + 1:]
        elif full_oid == oid:
            index = ""
        else:
            continue
        result[index] = value
    return result

def get_as_name(asn, session, cache):
    if not asn:
        return "DESCONHECIDO"
    if asn in cache:
        return cache[asn]
    try:
        r = session.get(
            "https://www.peeringdb.com/api/net",
            params={"asn": asn},
            timeout=6,
        )
        if r.ok:
            data = r.json()
            name = (data.get("data") or [{}])[0].get("name")
            if name and isinstance(name, str):
                cache[asn] = name
                return name
    except Exception:
        pass
    cache[asn] = "DESCONHECIDO"
    return "DESCONHECIDO"

def build_lld(host, community, port):
    as_map = run_snmpwalk(host, community, port, OID_AS)
    rem_map = run_snmpwalk(host, community, port, OID_REMOTE)
    status_map = run_snmpwalk(host, community, port, OID_STATUS)

    session = requests.Session()
    cache = {}

    results = []
    for idx in sorted(set(as_map) | set(rem_map) | set(status_map)):
        asn = str(as_map.get(idx, "")).strip()
        remote = str(rem_map.get(idx, "")).strip()
        status = str(status_map.get(idx, "")).strip()
        if not asn and not remote and not status:
            continue
        as_name = get_as_name(asn, session, cache)
        results.append({
            "{#SNMPINDEX}": idx,
            "{#AS}": asn,
            "{#REMOTEADD}": remote,
            "{#ASNNAME}": as_name or "DESCONHECIDO",
            "{#STATUS}": status
        })
    return results

def main():
    parser = argparse.ArgumentParser(
        description="LLD via SNMP + PeeringDB (AS, Remote, ASN Name, STATUS)"
    )
    parser.add_argument("community", help="Community SNMP v2c")
    parser.add_argument("host", help="IP/FQDN do equipamento")
    parser.add_argument("port", help="Porta SNMP (normalmente 161)")
    args = parser.parse_args()

    try:
        data = build_lld(args.host, args.community, args.port)
        print(json.dumps(data, ensure_ascii=False))
    except Exception as e:
        sys.stderr.write(f"ERRO: {e}\n")
        print("[]")
        sys.exit(1)

if __name__ == "__main__":
    main()
