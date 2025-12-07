#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request
import sqlite3
import json
import os

DB_PATH = "/var/log/snmptrapd/traps.db"

app = Flask(__name__, template_folder="templates")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/alarms")
def api_alarms():
    limit = int(request.args.get("limit", 400))
    include_cleared = request.args.get("include_cleared", "0") == "1"

    where_clause = ""
    if not include_cleared:
        # severity is inside parsed JSON, so filter after reading
        where_clause = ""

    query = f"""
        SELECT received_at, sender, parsed
        FROM traps
        ORDER BY received_at DESC
        LIMIT ?
    """

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(query, (limit,))
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        print("DB ERROR:", e)
        return jsonify({"alarms": []})

    alarms = []

    for row in rows:
        try:
            pdata = json.loads(row["parsed"]) if row["parsed"] else {}
        except:
            pdata = {}

        sev = (pdata.get("severity") or "").lower()

        if not include_cleared and sev == "cleared":
            continue

        alarms.append({
            "received_at": row["received_at"],
            "ne_name": pdata.get("ne_name", pdata.get("device", "-")),
            "ne_ip": row["sender"],
            "severity": sev,
            "trap_name": pdata.get("trap_name", pdata.get("trap", "-")),
            "category": pdata.get("category", "-"),
            "location": pdata.get("location", "-"),
            "alarm_time": pdata.get("alarm_time", row["received_at"]),
            "description": pdata.get("description", row["raw"] if "raw" in row else ""),
        })

    return jsonify({"alarms": alarms})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
