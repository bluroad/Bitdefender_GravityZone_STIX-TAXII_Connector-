#!/usr/bin/env python3
"""
gz_ioc_connector.py - IOC ingestion connector for Bitdefender GravityZone Cloud.

Sources  : MISP (REST), TAXII 2.1 (STIX indicators), local file (txt/csv)
Target   : GravityZone Public API (JSON-RPC 2.0) -> Incidents > addToBlocklist

Install  : pip install requests taxii2-client
Config   : environment variables (see Config) or CLI flags
Example  : python gz_ioc_connector.py --source misp --dry-run
           python gz_ioc_connector.py --source taxii --since 2026-10-01T00:00:00Z
           python gz_ioc_connector.py --source file --file iocs.csv

What gets pushed (addToBlocklist v1.2, per the public API docs):
  * HASHES (md5, sha256)  -> type = hash
  * IPs (v4/v6)           -> type = connection, remoteAddress.ipMask = <ip>,
                             protocol any, direction both
  * Domains / URLs        -> NOT supported by this API method (connection rules
    are IP-level). They are written to a CSV so nothing is lost; enforce them
    with other modules (Network Protection / Content Control).

Requirements on the endpoints: Blocklist module enabled in the policy, with
"Connection rules" ticked, and the Firewall module installed (connection
blocking does not work without it).
"""
from __future__ import annotations

import argparse
import base64
import csv
import ipaddress
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

import requests

log = logging.getLogger("gz-ioc")

# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #
HASH_LEN = {"md5": 32, "sha256": 64}
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


@dataclass(frozen=True)
class IOC:
    type: str    # md5 | sha256 | ip | domain | url
    value: str
    source: str = ""

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value}"


def normalize(raw_type: str, value: str, source: str) -> IOC | None:
    """Validate and normalise one indicator; return None if unusable."""
    t, v = raw_type.lower().strip(), value.strip()
    if not v:
        return None
    if t in ("md5", "sha256"):
        v = v.lower()
        return IOC(t, v, source) if len(v) == HASH_LEN[t] and HEX_RE.match(v) else None
    if t in ("ip", "ip-dst", "ip-src", "ipv4-addr", "ipv6-addr"):
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return None
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return None
        return IOC("ip", str(ip), source)
    if t in ("domain", "hostname", "domain-name"):
        v = v.lower().rstrip(".")
        return IOC("domain", v, source) if DOMAIN_RE.match(v) else None
    if t == "url":
        return IOC("url", v, source) if re.match(r"^https?://", v, re.I) else None
    return None


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #
class MispSource:
    TYPES = ["md5", "sha256", "ip-dst", "ip-src", "domain", "hostname", "url"]

    def __init__(self, url: str, key: str, verify: bool | str, last: str = "7d"):
        self.url, self.key, self.verify, self.last = url.rstrip("/"), key, verify, last

    def fetch(self) -> Iterator[IOC]:
        body = {"returnFormat": "json", "type": self.TYPES, "to_ids": 1,
                "published": 1, "last": self.last, "limit": 5000, "page": 1}
        headers = {"Authorization": self.key, "Accept": "application/json",
                   "Content-Type": "application/json"}
        while True:
            r = requests.post(f"{self.url}/attributes/restSearch", json=body,
                              headers=headers, verify=self.verify, timeout=120)
            r.raise_for_status()
            attrs = r.json().get("response", {}).get("Attribute", [])
            for a in attrs:
                ioc = normalize(a.get("type", ""), a.get("value", ""), "misp")
                if ioc:
                    yield ioc
            if len(attrs) < body["limit"]:
                break
            body["page"] += 1


PATTERN_RE = re.compile(
    r"(?P<obj>file:hashes\.(?:'?(?P<algo>MD5|SHA-256)'?)|ipv4-addr:value|ipv6-addr:value|"
    r"domain-name:value|url:value)\s*=\s*'(?P<val>[^']+)'", re.I)


def parse_stix_pattern(pattern: str) -> Iterator[tuple[str, str]]:
    for m in PATTERN_RE.finditer(pattern):
        obj = m.group("obj").lower()
        if obj.startswith("file:hashes"):
            yield ("md5" if m.group("algo").upper() == "MD5" else "sha256"), m.group("val")
        elif obj.startswith("ipv"):
            yield "ip", m.group("val")
        elif obj.startswith("domain"):
            yield "domain", m.group("val")
        elif obj.startswith("url"):
            yield "url", m.group("val")


class TaxiiSource:
    """TAXII 2.1 collection. TAXII_URL = full collection URL."""

    def __init__(self, collection_url: str, user: str, password: str, since: str | None):
        self.url, self.user, self.password, self.since = collection_url, user, password, since

    def fetch(self) -> Iterator[IOC]:
        from taxii2client.v21 import Collection  # lazy import
        coll = Collection(self.url, user=self.user, password=self.password)
        kwargs = {"type": "indicator"}
        if self.since:
            kwargs["added_after"] = self.since
        envelope = coll.get_objects(**kwargs)
        while True:
            for obj in envelope.get("objects", []):
                if obj.get("type") != "indicator" or obj.get("revoked"):
                    continue
                if obj.get("pattern_type", "stix") != "stix":
                    continue
                for t, v in parse_stix_pattern(obj.get("pattern", "")):
                    ioc = normalize(t, v, "taxii")
                    if ioc:
                        yield ioc
            if not envelope.get("more"):
                break
            kwargs["next"] = envelope.get("next")
            envelope = coll.get_objects(**kwargs)


class FileSource:
    """One IOC per line: 'value' (type auto-detected) or 'type,value' CSV."""

    def __init__(self, path: str):
        self.path = path

    @staticmethod
    def _guess(v: str) -> str:
        if HEX_RE.match(v) and len(v) in (32, 64):
            return "md5" if len(v) == 32 else "sha256"
        if v.lower().startswith(("http://", "https://")):
            return "url"
        try:
            ipaddress.ip_address(v)
            return "ip"
        except ValueError:
            return "domain"

    def fetch(self) -> Iterator[IOC]:
        with open(self.path, newline="", encoding="utf-8") as fh:
            for row in csv.reader(fh):
                if not row or row[0].startswith("#"):
                    continue
                t, v = (row[0], row[1]) if len(row) > 1 else (self._guess(row[0].strip()), row[0])
                ioc = normalize(t, v, "file")
                if ioc:
                    yield ioc


# --------------------------------------------------------------------------- #
# GravityZone client
# --------------------------------------------------------------------------- #
class GravityZone:
    """JSON-RPC 2.0 client. Auth: HTTP Basic, API key as username, empty password."""

    def __init__(self, api_url: str, api_key: str, company_id: str | None = None):
        self.endpoint = api_url.rstrip("/") + "/v1.0/jsonrpc/incidents"
        token = base64.b64encode(f"{api_key}:".encode()).decode()
        self.headers = {"Content-Type": "application/json", "Authorization": f"Basic {token}"}
        self.company_id = company_id
        self._id = 0

    def _call(self, method: str, params: dict, retries: int = 4):
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": str(self._id), "method": method, "params": params}
        for attempt in range(retries):
            r = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=60)
            if r.status_code == 429:                      # rate limited
                time.sleep(2 ** attempt)
                continue
            r.raise_for_status()
            body = r.json()
            if "error" in body:
                raise RuntimeError(f"GravityZone error: {body['error']}")
            return body["result"]
        raise RuntimeError("GravityZone: rate limit retries exhausted")

    def add_hashes(self, iocs: list[IOC], note: str) -> bool:
        params: dict = {
            "type": "hash",
            "rules": [{"note": note,
                       "details": {"algorithm": i.type, "hash": i.value}} for i in iocs],
        }
        if self.company_id:
            params["companyId"] = self.company_id
        return bool(self._call("addToBlocklist", params))

    @staticmethod
    def connection_rule(ioc: IOC, note: str) -> dict:
        """Connection rule blocking all traffic (any protocol, both directions)
        to/from a single remote IP. Field names per addToBlocklist v1.2 docs:
        details.{ruleName, protocol, direction, ipVersion} are mandatory;
        remoteAddress.{any (mandatory), ipMask (when any=false), portRange}."""
        version = "IPV6" if ":" in ioc.value else "IPV4"
        return {
            "note": note,
            "details": {
                "ruleName": f"IOC {ioc.value}",
                "protocol": "any",
                "direction": "both",
                "ipVersion": version,
                "remoteAddress": {"any": False, "ipMask": ioc.value},
            },
        }

    def add_connection_rules(self, iocs: list[IOC], note: str) -> bool:
        params: dict = {"type": "connection",
                        "rules": [self.connection_rule(i, note) for i in iocs]}
        if self.company_id:
            params["companyId"] = self.company_id
        return bool(self._call("addToBlocklist", params))




# --------------------------------------------------------------------------- #
# State (idempotency) and orchestration
# --------------------------------------------------------------------------- #
class State:
    def __init__(self, path: Path):
        self.path = path
        self.seen: set[str] = set(json.loads(path.read_text())) if path.exists() else set()

    def save(self):
        self.path.write_text(json.dumps(sorted(self.seen)))


def chunks(seq: list, n: int) -> Iterable[list]:
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def main() -> int:
    env = os.environ.get
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", required=True, choices=["misp", "taxii", "file"])
    ap.add_argument("--file", help="input file for --source file")
    ap.add_argument("--since", help="TAXII added_after (ISO 8601)")
    ap.add_argument("--misp-last", default="7d", help="MISP time window, e.g. 1d, 7d")
    ap.add_argument("--batch-size", type=int, default=50)
    ap.add_argument("--state", default="gz_ioc_state.json")
    ap.add_argument("--unsupported-out", default="iocs_not_pushed.csv")
    ap.add_argument("--note", default="Imported by gz_ioc_connector")
    ap.add_argument("--no-ip", action="store_true", help="do not push IPs as connection rules")
    ap.add_argument("--dry-run", action="store_true", help="parse and report, do not call GravityZone")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    verify: bool | str = env("TLS_CA_BUNDLE") or True

    if a.source == "misp":
        src = MispSource(env("MISP_URL", ""), env("MISP_KEY", ""), verify, a.misp_last)
    elif a.source == "taxii":
        src = TaxiiSource(env("TAXII_URL", ""), env("TAXII_USER", ""), env("TAXII_PASSWORD", ""), a.since)
    else:
        if not a.file:
            ap.error("--file is required with --source file")
        src = FileSource(a.file)

    state = State(Path(a.state))
    collected: dict[str, IOC] = {}
    for ioc in src.fetch():
        if ioc.key not in state.seen:
            collected[ioc.key] = ioc
    iocs = list(collected.values())
    hashes = [i for i in iocs if i.type in HASH_LEN]
    ips = [] if a.no_ip else [i for i in iocs if i.type == "ip"]
    others = [i for i in iocs if i.type not in HASH_LEN and i not in ips]
    log.info("new IOCs: %d (hashes=%d, ips=%d, domain/url/other=%d)",
             len(iocs), len(hashes), len(ips), len(others))

    if others:
        with open(a.unsupported_out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["type", "value", "source"])
            w.writerows((i.type, i.value, i.source) for i in others)
        log.warning("%d IOCs (domain/url) written to %s: not supported by addToBlocklist", len(others), a.unsupported_out)

    if a.dry_run:
        log.info("dry-run: nothing sent")
        return 0

    gz_url, gz_key = env("GZ_API_URL"), env("GZ_API_KEY")
    if not gz_url or not gz_key:
        log.error("GZ_API_URL and GZ_API_KEY are required")
        return 2
    gz = GravityZone(gz_url, gz_key, env("GZ_COMPANY_ID"))

    pushed = failed = 0
    for items, send in ((hashes, gz.add_hashes), (ips, gz.add_connection_rules)):
        for batch in chunks(items, a.batch_size):
            try:
                send(batch, a.note)
                state.seen.update(i.key for i in batch)
                pushed += len(batch)
            except Exception as exc:                   # keep going, retry next run
                failed += len(batch)
                log.error("batch failed (%d items): %s", len(batch), exc)
            time.sleep(0.2)                             # stay well under the rate limit
    state.save()
    log.info("done: pushed=%d failed=%d", pushed, failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
