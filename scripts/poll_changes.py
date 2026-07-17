"""
poll_changes.py

Polls a local changedetection.io instance's REST API for watches that have
changed since the last run, and appends a plain-English digest entry to a
markdown file in Andrew's Obsidian vault (a folder Cowork already reads).

Runs entirely locally (stdlib only, no pip installs needed) via Windows Task
Scheduler on a timer -- NOT inside Docker, and NOT as a Cowork scheduled task,
because Cowork's scheduled tasks run in a cloud sandbox with no path to
http://localhost, and this instance isn't exposed past 127.0.0.1.

Config is via environment variables (set these in the Task Scheduler action,
not hardcoded here, so nothing sensitive lives in this file):
  CD_API_BASE    - default http://localhost:5000
  CD_API_KEY     - optional. Only needed if "Enable API access" + a token are
                   set in changedetection's Settings -> API. Leave unset if
                   you left API access disabled (fine for localhost-only use).
  CD_ALERTS_FILE - default: the vault's notes/changedetection-alerts.md
  CD_STATE_FILE  - default: ./datastore/.poll_state.json (already .gitignore'd)

State (which watches we've already alerted on) is a small local JSON cache,
keyed by watch UUID -> last_changed timestamp we've already surfaced.
"""

import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

API_BASE = os.environ.get("CD_API_BASE", "http://localhost:5000").rstrip("/")
API_KEY = os.environ.get("CD_API_KEY", "")
ALERTS_FILE = Path(os.environ.get(
    "CD_ALERTS_FILE",
    r"C:\Users\andrew\OneDrive - evensun.com\amsEvensun\notes\changedetection-alerts.md",
))
STATE_FILE = Path(os.environ.get(
    "CD_STATE_FILE",
    str(Path(__file__).resolve().parent.parent / "datastore" / ".poll_state.json"),
))
DIFF_MAX_CHARS = 4000


def _request(path, params=None):
    url = f"{API_BASE}{path}"
    if params:
        from urllib.parse import urlencode
        url += "?" + urlencode(params)
    req = urllib.request.Request(url)
    if API_KEY:
        req.add_header("x-api-key", API_KEY)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _request_text(path, params=None):
    url = f"{API_BASE}{path}"
    if params:
        from urllib.parse import urlencode
        url += "?" + urlencode(params)
    req = urllib.request.Request(url)
    if API_KEY:
        req.add_header("x-api-key", API_KEY)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", errors="replace")


def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def get_diff_text(uuid):
    """Best-effort plain-text diff between the previous and latest snapshot."""
    try:
        return _request_text(
            f"/api/v1/watch/{uuid}/difference/previous/latest",
            params={"format": "text", "changesOnly": "true"},
        )
    except urllib.error.HTTPError as e:
        return f"(couldn't fetch diff: HTTP {e.code} -- likely only one snapshot exists so far)"
    except Exception as e:
        return f"(couldn't fetch diff: {e})"


def main():
    try:
        watches = _request("/api/v1/watch")
    except urllib.error.URLError as e:
        # changedetection isn't reachable (container stopped, wrong port, etc).
        # Fail quietly-ish -- Task Scheduler will just try again next run.
        print(f"Could not reach changedetection at {API_BASE}: {e}")
        return

    state = load_state()
    new_entries = []

    for uuid, w in watches.items():
        last_changed = w.get("last_changed") or 0
        if not last_changed:
            continue  # never checked or never changed

        seen = state.get(uuid, 0)
        if last_changed <= seen:
            continue  # nothing new since last run

        title = w.get("title") or w.get("page_title") or w.get("url")
        when = datetime.fromtimestamp(last_changed, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        diff_text = get_diff_text(uuid)
        if len(diff_text) > DIFF_MAX_CHARS:
            diff_text = diff_text[:DIFF_MAX_CHARS] + "\n... (truncated)"

        entry = (
            f"### {title} — {when}\n\n"
            f"- Watch: {w.get('url')}\n"
            f"- Open in UI: {API_BASE}/diff/{uuid}\n\n"
            f"```\n{diff_text}\n```\n"
        )
        new_entries.append(entry)
        state[uuid] = last_changed

    if new_entries:
        ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        run_header = f"\n## Poll run — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n"
        with ALERTS_FILE.open("a", encoding="utf-8") as f:
            f.write(run_header)
            f.write("\n".join(new_entries))
            f.write("\n")
        save_state(state)
        print(f"Wrote {len(new_entries)} new change(s) to {ALERTS_FILE}")
    else:
        print("No new changes since last run.")


if __name__ == "__main__":
    main()
