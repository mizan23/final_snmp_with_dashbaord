#!/usr/bin/env python3
"""
SNMP trap DB handler & viewer

- When run without a subcommand it acts as the trap handler (snmptrapd mode),
  reading the trap text from stdin and storing parsed JSON into /var/log/snmptrapd/traps.db.

- When run with subcommands (view, stats, raw, follow) it acts as a CLI viewer
  for the stored traps DB.
"""
from __future__ import annotations

import sys
import os
import re
import json
import sqlite3
import argparse
import logging
import time
from datetime import datetime
from zoneinfo import ZoneInfo
from typing import Optional

# -------------------------
# Configuration
# -------------------------

DBDIR = "/var/log/snmptrapd"
DB = os.path.join(DBDIR, "traps.db")
TZ = ZoneInfo("Asia/Dhaka")
RETENTION_DAYS = 7

os.makedirs(DBDIR, exist_ok=True)

# -------------------------
# DB helpers
# -------------------------

def get_conn(dbpath: Optional[str] = None) -> sqlite3.Connection:
    """Return a sqlite connection to the traps DB. If dbpath provided, use that."""
    if dbpath is None:
        dbpath = os.getenv("SNMP_TRAPS_DB", DB)
    conn = sqlite3.connect(dbpath)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS traps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      received_at TEXT,
      sender TEXT,
      raw TEXT,
      parsed TEXT
    )
    """)

    c.execute("CREATE INDEX IF NOT EXISTS idx_traps_received_at ON traps(received_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_traps_sender ON traps(sender)")

    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA synchronous=NORMAL;")
    c.execute("PRAGMA foreign_keys=ON;")
    return conn


def cleanup_old_rows(c: sqlite3.Cursor):
    # handle both "YYYY-MM-DD HH:MM:SS" and old ISO strings
    c.execute(f"""
        DELETE FROM traps
        WHERE (
          substr(received_at,11,1) = ' '
          AND received_at < strftime('%Y-%m-%d %H:%M:%S', 'now', '-{RETENTION_DAYS} days', 'localtime')
        )
        OR (
          substr(received_at,11,1) = 'T'
          AND substr(received_at,1,10) < strftime('%Y-%m-%d', 'now', '-{RETENTION_DAYS} days', 'localtime')
        )
    """)
    c.execute("PRAGMA optimize;")

# -------------------------
# OID helpers
# -------------------------

def normalize_oid(oid: str) -> str:
    s = oid.strip()
    if s.startswith("iso."):
        s = "1." + s[4:]
    return s


OID_FRIENDLY_NAMES = {
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
    "SNMPv2-MIB::sysUpTime.0": "sysUpTime",
    "DISMAN-EVENT-MIB::sysUpTimeInstance": "sysUpTime",
    "1.3.6.1.6.3.1.1.4.1.0": "snmpTrapOID",
    "SNMPv2-MIB::snmpTrapOID.0": "snmpTrapOID",
}

# Huawei alarm OID field mapping (common 2011.2.15.1.7.1.*.0)
HUAWEI_FIELDS = {
    "1.3.6.1.4.1.2011.2.15.1.7.1.1.0": ("neName",        "NE name"),
    "1.3.6.1.4.1.2011.2.15.1.7.1.2.0": ("neType",        "Product / NE type"),
    "1.3.6.1.4.1.2011.2.15.1.7.1.3.0": ("source",        "Source / location"),
    "1.3.6.1.4.1.2011.2.15.1.7.1.4.0": ("category",      "Category"),
    "1.3.6.1.4.1.2011.2.15.1.7.1.5.0": ("alarmTime",     "Alarm time"),
    "1.3.6.1.4.1.2011.2.15.1.7.1.6.0": ("description",   "Description"),
    "1.3.6.1.4.1.2011.2.15.1.7.1.7.0": ("severityText",  "Severity text"),
    "1.3.6.1.4.1.2011.2.15.1.7.1.8.0": ("alarmNameText", "Alarm name text"),
    "1.3.6.1.4.1.2011.2.15.1.7.1.9.0": ("nodeId",        "Node ID"),
    "1.3.6.1.4.1.2011.2.15.1.7.1.10.0":("alarmStatus",   "Alarm status"),
    "1.3.6.1.4.1.2011.2.15.1.7.1.12.0":("neIp",          "NE IP"),
    "1.3.6.1.4.1.2011.2.15.1.7.1.24.0":("alarmCode",     "Alarm code"),
}

HUAWEI_SOURCE_OID = "1.3.6.1.4.1.2011.2.15.1.7.1.3.0"

def human_name_from_oid(oid: str) -> str:
    n = normalize_oid(oid)
    if n in OID_FRIENDLY_NAMES:
        return OID_FRIENDLY_NAMES[n]
    if n in HUAWEI_FIELDS:
        return HUAWEI_FIELDS[n][0]  # short field name
    if "::" in n:
        _, right = n.split("::", 1)
        right = re.sub(r"\.\d+$", "", right)
        return right
    parts = n.split(".")
    return parts[-1] if parts else n

# -------------------------
# Value parsing
# -------------------------

def guess_type(val: str) -> str:
    v = val.strip()
    if not v:
        return "STRING"
    if v.startswith('"'):
        return "STRING"
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", v):
        return "IPADDR"
    if re.match(r"^-?\d+(\.\d+)?$", v):
        return "INTEGER"
    if re.match(r"^(iso\.)?\d+(\.\d+)*$", v):
        return "OID"
    if re.match(r"^\d+:\d+:\d+:\d+(\.\d+)?$", v):
        return "TIMETICKS"
    return "STRING"


def parse_value(typ: str, val: str):
    t = typ.upper().strip()
    raw_val = val.strip().strip('"')

    if t in ("INTEGER", "COUNTER", "GAUGE", "COUNTER32", "COUNTER64"):
        m = re.search(r"(-?\d+)", raw_val)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                pass
        return raw_val

    if t == "TIMETICKS":
        return raw_val

    if t in ("OID", "OBJECT IDENTIFIER"):
        return {
            "oid": normalize_oid(raw_val),
            "name": human_name_from_oid(raw_val),
        }

    if t == "IPADDR":
        return raw_val

    return raw_val

# -------------------------
# Enrichment helper (for old rows)
# -------------------------

def enrich_meta_with_source(parsed: dict) -> None:
    """
    Ensure parsed['meta']['source'] is set if any var contains the Huawei source string,
    even for rows stored before HUAWEI_FIELDS was correct.
    """
    if not isinstance(parsed, dict):
        return
    meta = parsed.get("meta")
    if not isinstance(meta, dict):
        meta = {}
        parsed["meta"] = meta

    # If already present and non-empty, nothing to do
    if meta.get("source"):
        return

    vars_list = parsed.get("vars", [])
    if not isinstance(vars_list, list):
        return

    # 1) Look for exact Huawei source OID first
    for v in vars_list:
        if not isinstance(v, dict):
            continue
        oid = v.get("oid") or ""
        val = v.get("value")
        if oid == HUAWEI_SOURCE_OID and isinstance(val, str) and "source=" in val:
            meta["source"] = val
            return

    # 2) Fallback: any var value containing 'source=' and 'location='
    for v in vars_list:
        if not isinstance(v, dict):
            continue
        val = v.get("value")
        if isinstance(val, str) and "source=" in val and "location=" in val:
            meta["source"] = val
            return

# -------------------------
# Trap parsing
# -------------------------

def parse_trap(sender: str, raw: str, received_at: str):
    vars_list = []
    extra_lines = []
    derived_sender = sender
    huawei_meta_fields = {}

    # --- merge continuation lines so multi-line descriptions stay together ---
    raw_lines = (raw or "").splitlines()
    logical_lines = []
    for line in raw_lines:
        s = line.strip()
        if not s:
            continue

        # A new logical line starts if it looks like header/UDP/OID
        is_new_record = (
            s.startswith("<") and s.endswith(">")
            or s.startswith("UDP:")
            or s.startswith("iso.")
            or re.match(r"^\d+(\.\d+)*\s", s)  # starts with numeric OID
            or " = " in line                   # explicit "OID = TYPE: VALUE"
        )

        if is_new_record or not logical_lines:
            logical_lines.append(line)
        else:
            # Continuation line: append to previous line (space-separated)
            logical_lines[-1] += " " + s

    # Now parse the merged logical_lines instead of raw.splitlines()
    for line in logical_lines:
        s = line.strip()
        if not s:
            continue

        # Header like "<UNKNOWN>"
        if s.startswith("<") and s.endswith(">"):
            extra_lines.append(s)
            continue

        # UDP: [192.168.42.5]:6666->[192.168.74.91]:8899
        if s.startswith("UDP:"):
            m = re.search(r"UDP:\s*\[([^\]]+)\]", s)
            if m:
                derived_sender = m.group(1)
            extra_lines.append(s)
            continue

        # Format 1: "OID = TYPE: VALUE"
        # Only treat as this format if there is a real " = " in the line.
        m = None
        if " = " in line:
            m = re.match(r"^\s*([^=]+?)\s*=\s*([^:]+):\s*(.*)$", line)

        if m:
            oid = m.group(1).strip()
            typ = m.group(2).strip()
            val = m.group(3).strip()
        else:
            # Format 2: "OID VALUE"
            parts = line.split(None, 1)
            if len(parts) < 2:
                extra_lines.append(s)
                continue
            oid = parts[0].strip()
            val = parts[1].strip()
            typ = guess_type(val)

        norm_oid = normalize_oid(oid)
        name = human_name_from_oid(norm_oid)
        parsed_val = parse_value(typ, val)

        v_entry = {
            "oid": norm_oid,
            "name": name,
            "type": typ,
            "value": parsed_val,
            "raw_value": val.strip().strip('"'),
        }
        vars_list.append(v_entry)

        # collect Huawei dedicated meta
        if norm_oid in HUAWEI_FIELDS:
            field_key, _label = HUAWEI_FIELDS[norm_oid]
            huawei_meta_fields[field_key] = parsed_val

    # build meta
    meta = {}

    # sysUpTime & snmpTrapOID if present
    for v in vars_list:
        if v["name"] == "sysUpTime":
            meta["sysUpTime"] = v["value"]
        if v["name"] == "snmpTrapOID":
            val = v["value"]
            if isinstance(val, dict):
                meta["trapOID"] = val.get("oid")
                meta.setdefault("trapName", val.get("name"))
            else:
                meta["trapOID"] = val

    # merge Huawei fields to meta
    meta.update(huawei_meta_fields)

    # Determine trapName
    if "alarmCode" in huawei_meta_fields and isinstance(huawei_meta_fields["alarmCode"], str):
        meta["trapName"] = huawei_meta_fields["alarmCode"]
    elif "alarmNameText" in huawei_meta_fields and isinstance(huawei_meta_fields["alarmNameText"], str):
        meta["trapName"] = huawei_meta_fields["alarmNameText"]

    # Severity
    sev_txt = huawei_meta_fields.get("severityText")
    if isinstance(sev_txt, str):
        low = sev_txt.lower()
        if "critical" in low:
            meta["severity"] = "critical"
        elif "major" in low:
            meta["severity"] = "major"
        elif "minor" in low:
            meta["severity"] = "minor"
        elif "warning" in low:
            meta["severity"] = "warning"
        elif "cleared" in low or "recovery" in low:
            meta["severity"] = "cleared"

    # As a fallback, scan textual vars
    if "severity" not in meta:
        for v in vars_list:
            val = v["value"]
            if isinstance(val, str):
                low = val.lower()
                if "critical" in low:
                    meta["severity"] = "critical"; break
                if "major" in low:
                    meta["severity"] = "major"; break
                if "minor" in low:
                    meta["severity"] = "minor"; break
                if "warning" in low:
                    meta["severity"] = "warning"; break

    parsed = {
        "sender": derived_sender,
        "received_at": received_at,
        "meta": meta,
        "vars": vars_list,
    }
    if extra_lines:
        parsed["extra"] = extra_lines

    # Make sure source is set if possible
    enrich_meta_with_source(parsed)

    return parsed

# -------------------------
# Trap handler mode (called by snmptrapd)
# -------------------------

def handle_trap_mode():
    try:
        raw = sys.stdin.read()
    except Exception:
        raw = ""

    cli_sender = sys.argv[1] if len(sys.argv) > 1 else "UNKNOWN"
    received_at = datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")

    # HARD FILTER 1 (raw text):
    # Ignore Huawei SNMP Agent keepalive traps completely.
    # These always look like:
    #   iso.3.6.1.6.3.1.1.4.1.0 iso.3.6.1.4.1.2011.2.15.1.7.2.0.2
    #   iso.3.6.1.4.1.2011.2.15.1 "SNMP Agent"
    if "SNMP Agent" in raw and ".7.2.0.2" in raw:
        return

    # Parse trap for meta-based filtering
    parsed = parse_trap(cli_sender, raw, received_at)

    # HARD FILTER 2 (meta fields, backup / extra safety):
    meta = parsed.get("meta", {}) if isinstance(parsed, dict) else {}
    trap_name = str(meta.get("trapName") or "")
    trap_oid = str(meta.get("trapOID") or "")

    # If trapName is "2" or trapOID ends in .7.2.0.2, ignore.
    if trap_name == "2" or trap_oid.endswith(".7.2.0.2"):
        return

    conn = get_conn()
    c = conn.cursor()

    db_sender = parsed.get("sender", cli_sender)

    c.execute(
        "INSERT INTO traps (received_at, sender, raw, parsed) VALUES (?, ?, ?, ?)",
        (received_at, db_sender, raw, json.dumps(parsed, ensure_ascii=False)),
    )

    cleanup_old_rows(c)
    conn.commit()
    conn.close()

# -------------------------
# CLI helpers & viewer
# -------------------------

def get_parsed_row(row: sqlite3.Row):
    """Return parsed JSON; if missing/invalid, parse on the fly from raw.
       Also enrich meta['source'] for old rows."""
    parsed = None
    try:
        if row["parsed"]:
            parsed = json.loads(row["parsed"])
    except Exception:
        parsed = None
    if not isinstance(parsed, dict):
        parsed = parse_trap(row["sender"], row["raw"], row["received_at"])
    else:
        enrich_meta_with_source(parsed)
    return parsed


def cli_view(args):
    conn = get_conn(args.db)
    c = conn.cursor()

    where = []
    params = []

    if args.sender:
        where.append("sender LIKE ?")
        params.append(f"%{args.sender}%")
    if args.since:
        where.append("received_at >= ?")
        params.append(args.since)
    if args.until:
        where.append("received_at <= ?")
        params.append(args.until)

    q = "SELECT id, received_at, sender, raw, parsed FROM traps"
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(args.limit)

    rows = c.execute(q, params).fetchall()

    for row in rows:
        parsed = get_parsed_row(row)
        meta = parsed.get("meta", {}) if isinstance(parsed, dict) else {}

        trap_name = meta.get("trapName") or meta.get("alarmCode") or meta.get("alarmNameText") or meta.get("trapOID") or "unknown-trap"
        severity = meta.get("severity") or meta.get("severityText") or "info"
        ne_name = meta.get("neName") or meta.get("site") or ""
        category = meta.get("category") or ""
        alarm_time = meta.get("alarmTime") or ""
        ne_ip = meta.get("neIp") or row["sender"]
        source = meta.get("source") or ""

        print(f"[{row['id']}] {row['received_at']}  {ne_name or '-'}")
        print(f"  Sender : {ne_ip}")
        print(f"  Trap   : {trap_name}")
        print(f"  Sev    : {severity}")
        if category:
            print(f"  Cat    : {category}")
        if alarm_time:
            print(f"  AlarmT : {alarm_time}")
        if source:
            print(f"  Source : {source}")

        # short description
        desc = meta.get("description")
        if isinstance(desc, str) and desc:
            one_line = " ".join(desc.splitlines())
            print(f"  Desc   : {one_line[:140]}{'...' if len(one_line) > 140 else ''}")

        # show a few key vars (skip things we already showed)
        vars_list = parsed.get("vars", []) if isinstance(parsed, dict) else []
        shown = 0
        for v in vars_list:
            if v.get("name") in ("neName", "neIp", "alarmTime", "description",
                                 "severityText", "alarmCode", "alarmNameText",
                                 "category", "source"):
                continue
            print(f"    - {v['name']} ({v['type']}): {v['value']}")
            shown += 1
            if shown >= 5:
                break
        if len(vars_list) > shown + 8:
            print(f"    ... +{len(vars_list) - shown} more vars")
        print()

    conn.close()


def cli_stats(_args):
    conn = get_conn(_args.db) if hasattr(_args, "db") else get_conn()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) AS cnt FROM traps")
    total = c.fetchone()["cnt"]

    c.execute("SELECT received_at FROM traps ORDER BY received_at ASC LIMIT 1")
    row_old = c.fetchone()
    c.execute("SELECT received_at FROM traps ORDER BY received_at DESC LIMIT 1")
    row_new = c.fetchone()

    c.execute("SELECT sender, COUNT(*) AS cnt FROM traps GROUP BY sender ORDER BY cnt DESC")
    per_sender = c.fetchall()

    print(f"Total traps : {total}")
    if row_old and row_new:
        print(f"Oldest trap : {row_old['received_at']}")
        print(f"Newest trap : {row_new['received_at']}")
    print()
    print("By sender:")
    for row in per_sender:
        print(f"  {row['sender']}: {row['cnt']}")

    conn.close()


def cli_raw(args):
    conn = get_conn(args.db)
    c = conn.cursor()

    if args.id is not None:
        c.execute("SELECT id, received_at, sender, raw, parsed FROM traps WHERE id = ?", (args.id,))
    else:
        c.execute(
            "SELECT id, received_at, sender, raw, parsed FROM traps ORDER BY id DESC LIMIT ?",
            (args.limit,),
        )
    rows = c.fetchall()

    for row in rows:
        parsed = get_parsed_row(row)
        meta = parsed.get("meta", {}) if isinstance(parsed, dict) else {}

        trap_name = meta.get("trapName") or meta.get("alarmCode") or meta.get("alarmNameText") or meta.get("trapOID") or "unknown-trap"
        severity = meta.get("severity") or meta.get("severityText") or "info"
        ne_name = meta.get("neName") or ""
        source = meta.get("source") or ""

        print("=" * 60)
        print(f"ID       : {row['id']}")
        print(f"Time     : {row['received_at']}")
        print(f"Sender   : {row['sender']}")
        print(f"NE       : {ne_name or '-'}")
        print(f"Trap     : {trap_name}")
        print(f"Severity : {severity}")
        if source:
            print(f"Source   : {source}")
        print("-" * 60)

        raw_text = (row["raw"] or "").rstrip()
        if not getattr(args, "full", False) and len(raw_text) > 400:
            print(raw_text[:400] + "\n... (truncated, use --full to show all)")
        else:
            print(raw_text)
        print()

    conn.close()


def cli_follow(args):
    """Follow new traps in the DB (like tail -f)."""
    dbpath = args.db or os.getenv("SNMP_TRAPS_DB", DB)
    conn = sqlite3.connect(dbpath)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT id FROM traps ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    last_id = row["id"] if row else 0

    try:
        while True:
            cur.execute("SELECT id, received_at, sender, raw, parsed FROM traps WHERE id > ? ORDER BY id ASC", (last_id,))
            rows = cur.fetchall()
            if rows:
                for r in rows:
                    last_id = r["id"]
                    parsed = get_parsed_row(r)
                    meta = parsed.get("meta", {}) if isinstance(parsed, dict) else {}
                    trap_name = meta.get("trapName") or meta.get("alarmCode") or meta.get("alarmNameText") or meta.get("trapOID") or "unknown-trap"
                    severity = meta.get("severity") or meta.get("severityText") or "info"
                    ne_name = meta.get("neName") or ""
                    source = meta.get("source") or ""

                    print("="*60)
                    print(f"ID       : {r['id']}")
                    print(f"Time     : {r['received_at']}")
                    print(f"Sender   : {r['sender']}")
                    print(f"NE       : {ne_name or '-'}")
                    print(f"Trap     : {trap_name}")
                    print(f"Severity : {severity}")
                    if source:
                        print(f"Source   : {source}")
                    print("-"*60)

                    payload = r["raw"] or ""
                    if not getattr(args, "full", False) and len(str(payload)) > 400:
                        print(str(payload)[:400] + "\n... (truncated, use --full to show all)")
                    else:
                        print((payload or "").rstrip())
                    print()
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nStopped following.")
    finally:
        conn.close()

# -------------------------
# CLI plumbing
# -------------------------

def parse_time_arg(s: Optional[str]) -> Optional[str]:
    """Accept 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS'. Return normalized string for SQL or raise ValueError."""
    if not s:
        return None
    s = s.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            if fmt == "%Y-%m-%d %H:%M:%S":
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            return dt.strftime("%Y-%m-%d")
        except Exception:
            continue
    raise ValueError(f"Bad date format: {s!r}. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")


def cli_main(argv):
    parser = argparse.ArgumentParser(
        description="SNMP trap DB viewer for /var/log/snmptrapd/traps.db"
    )
    parser.add_argument("--db", help="Path to traps.db (or set SNMP_TRAPS_DB env var)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_view = subparsers.add_parser("view", help="Show recent traps with summary (human readable)")
    p_view.add_argument("--limit", type=int, default=20, help="Max rows (default: 20)")
    p_view.add_argument("--sender", help="Filter by sender (LIKE pattern)")
    p_view.add_argument("--since", help="Filter received_at >= (YYYY-MM-DD or timestamp)")
    p_view.add_argument("--until", help="Filter received_at <= (YYYY-MM-DD or timestamp)")
    p_view.set_defaults(func=cli_view)

    p_stats = subparsers.add_parser("stats", help="Show DB statistics")
    p_stats.set_defaults(func=cli_stats)

    p_raw = subparsers.add_parser("raw", help="Show raw stored trap text")
    p_raw.add_argument("--id", type=int, help="Show raw for a specific trap ID")
    p_raw.add_argument("--limit", type=int, default=5, help="Show last N raw traps if --id not given")
    p_raw.add_argument("--full", action="store_true", help="Show full raw payload (no truncation)")
    p_raw.set_defaults(func=cli_raw)

    p_follow = subparsers.add_parser("follow", help="Follow new traps (like tail -f)")
    p_follow.add_argument("--full", action="store_true", help="Show full raw payload")
    p_follow.set_defaults(func=cli_follow)

    args = parser.parse_args(argv)

    # logging
    if args.__dict__.get("debug"):
        logging.basicConfig(level=logging.DEBUG)

    # validate date args early
    try:
        if hasattr(args, "since") and args.since:
            args.since = parse_time_arg(args.since)
        if hasattr(args, "until") and args.until:
            args.until = parse_time_arg(args.until)
    except ValueError as e:
        parser.error(str(e))

    # set DB path via env var for downstream helpers
    if args.db:
        os.environ["SNMP_TRAPS_DB"] = args.db

    try:
        args.func(args)
    except KeyboardInterrupt:
        print("Interrupted.")
        raise SystemExit(1)
    except Exception as e:
        logging.exception("Command failed")
        print(f"Error: {e}")
        raise SystemExit(2)

# -------------------------
# Entry point
# -------------------------

if __name__ == "__main__":
    # CLI mode vs snmptrapd mode
    if len(sys.argv) > 1 and sys.argv[1] in {"view", "stats", "raw", "follow"}:
        cli_main(sys.argv[1:])
    else:
        handle_trap_mode()
