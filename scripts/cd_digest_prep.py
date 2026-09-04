#!/usr/bin/env python3
"""
cd_digest_prep.py -- deterministic pre-processor for the change detection digest.

Reads a changedetection.io datastore, finds every snapshot recorded since the
last run, diffs each one against its immediate predecessor, and writes:

  <datastore>/diffs/YYYY-MM-DD/<uuid>__<ts>.diff   full archived diff (URLs intact)
  <datastore>/diffs/YYYY-MM-DD/_packet.md          compact work packet for the agent
  <datastore>/diffs/YYYY-MM-DD/_volume.json        run-size metrics

No LLM, no network, no writes anywhere except <datastore>/diffs/ and the state
file. Safe to run repeatedly: --dry-run leaves state untouched.

State lives at <datastore>/.cowork_seen.json and records, per watch UUID, the
last history.txt line already processed.

Design notes that matter (see notes/Change Detection Monitoring.md):
  * history.txt is the only source of truth for which snapshots exist. Some
    watches have more snapshot FILES on disk than history lines (orphans from
    retention trims), so never enumerate the directory.
  * Retention trimming means a previously-seen line can vanish. When the stored
    line is gone we fall back to "process anything newer than its timestamp".
  * render_anchor_tag_content is ON, so snapshots carry markdown [text](url).
    URLs are kept for DETECTION (Georgia Access PUFs change only inside the
    href) and for the archived diffs, but stripped out of the work packet the
    agent reads -- Andrew wants watch-level links only.
  * Snapshots are plain .txt or brotli .txt.br.

Usage:
  python cd_digest_prep.py --seed            # mark everything current as seen, exit
  python cd_digest_prep.py --dry-run         # process, write nothing, print summary
  python cd_digest_prep.py                   # process, write packet + archive, advance state
"""

from __future__ import annotations

import argparse
import difflib
import importlib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

# --------------------------------------------------------------------------
# brotli is not preinstalled in the Cowork sandbox (verified 2026-09-02 by the
# cd-plumbing-smoke-test task). Bootstrap it rather than fail the run.
#
# If the bootstrap fails, `brotli` stays None and every .txt.br snapshot this
# run is unreadable -- that's an operational problem, not a per-watch quirk,
# so we keep the pip failure reason around (`_BROTLI_INSTALL_ERROR`) and
# surface it via health_report() once we know how many snapshots it actually
# affected (see `brotli_skipped` in main()), rather than letting it hide
# inside individual watch sections.
#
# Root cause found 2026-09-04: pip installing brotli into a subprocess does
# not make it visible to THIS already-running interpreter -- Python's import
# system caches negative lookups (a module it already failed to find) made
# before the package existed on disk, in `sys.path_importer_cache`. Without
# invalidating that cache, the retry `import brotli` below fails even though
# the package is genuinely on disk and importable in a fresh process (this
# is exactly what happened on 09-03 and again on 09-04: pip exited 0 with no
# output, i.e. success, and a fresh shell right after had brotli available).
# `importlib.invalidate_caches()` forces Python to re-scan sys.path before
# the retry, which is the actual fix -- everything before this was reporting
# the symptom loudly, not curing it.
# --------------------------------------------------------------------------
_BROTLI_INSTALL_ERROR: str | None = None
try:
    import brotli  # type: ignore
except ImportError:  # pragma: no cover
    _install = subprocess.run(
        [sys.executable, "-m", "pip", "install", "brotli",
         "--break-system-packages", "-q"],
        check=False, capture_output=True, text=True,
    )
    importlib.invalidate_caches()
    try:
        import brotli  # type: ignore
    except ImportError:
        brotli = None  # handled per-file; .txt snapshots still work
        _BROTLI_INSTALL_ERROR = (
            (_install.stderr or _install.stdout or "").strip()
            or f"pip install exited {_install.returncode} with no output"
        )

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASTORE = REPO_ROOT / "datastore"

WS_RE = re.compile(r"\s+")
BULLET_RE = re.compile(r"^[\*\+\-o]\s+")

# Per-snapshot reporting caps. Full detail always lands in the .diff archive.
MAX_LINES_PER_SIDE = 30
MAX_LINK_CHANGES = 12
STALE_HOURS = 6


# --------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------

def read_snapshot(path: Path) -> str:
    raw = path.read_bytes()
    if path.name.endswith(".br"):
        if brotli is None:
            return ""
        try:
            raw = brotli.decompress(raw)
        except Exception:
            pass
    return raw.decode("utf-8", "replace")


def norm_lines(text: str) -> list[str]:
    """Collapse whitespace runs and drop blank lines.

    WA DES snapshots are ~91% runs of 5+ spaces; this alone takes that watch
    from ~29 KB to ~2.5 KB.
    """
    out = []
    for line in text.splitlines():
        line = WS_RE.sub(" ", line).strip()
        if line:
            out.append(line)
    return out


def _anchor_url_end(line: str, start: int) -> int:
    """Index of the ')' that closes a `](url)` group starting at `start`
    (the char right after the '(').

    Depth-counts parens rather than stopping at the first ')', because
    hbex.coveredca.com filenames land in the URL with a nested `(...)` intact
    (e.g. `.../QHP Individual Rates (surcharge) 10-18-17.xlsx`) -- a naive
    "stop at first )" match truncates the URL there instead of at the real
    end. Returns -1 if the parens never balance back to zero.
    """
    depth = 1
    n = len(line)
    i = start
    while i < n:
        c = line[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def iter_anchors(line: str):
    """Yield (start, end, text, url) for each markdown `[text](url)` anchor.

    Deliberately more permissive than strict CommonMark: URLs may contain
    spaces (hbex.coveredca.com filenames do -- e.g. `2027 Plans by Zip -
    Individual.xlsx`) and balanced nested parens. `end` is exclusive (index
    just past the closing ')'), so callers can slice/replace in place.
    """
    i, n = 0, len(line)
    while i < n:
        lb = line.find("[", i)
        if lb == -1:
            return
        rb = line.find("]", lb + 1)
        if rb == -1:
            return
        if rb + 1 >= n or line[rb + 1] != "(":
            i = lb + 1
            continue
        close = _anchor_url_end(line, rb + 2)
        if close == -1:
            i = lb + 1
            continue
        yield lb, close + 1, line[lb + 1:rb], line[rb + 2:close]
        i = close + 1


def strip_urls(line: str) -> str:
    out = []
    last = 0
    for start, end, text, _url in iter_anchors(line):
        out.append(line[last:start])
        out.append(text.strip())
        last = end
    out.append(line[last:])
    return "".join(out).strip()


def urls_in(line: str) -> list[str]:
    return [url for _start, _end, _text, url in iter_anchors(line)]


def url_tail(url: str) -> str:
    """The part of a URL a human would recognise -- usually the filename."""
    tail = url.split("?")[0].rstrip("/").split("/")[-1]
    return tail or url


def history_entries(watch_dir: Path) -> list[tuple[int, str, str]]:
    """[(unix_ts, snapshot_filename, raw_line)] in file order."""
    hist = watch_dir / "history.txt"
    if not hist.exists():
        return []
    entries = []
    for raw in hist.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw or "," not in raw:
            continue
        ts_s, fname = raw.split(",", 1)
        try:
            entries.append((int(ts_s), fname.strip(), raw))
        except ValueError:
            continue
    return entries


# --------------------------------------------------------------------------
# diffing
# --------------------------------------------------------------------------

def compare(prev_text: str, curr_text: str) -> dict:
    """Two-stage comparison.

    Stage 1 -- content: diff the URL-stripped lines. This is what a human means
    by "the page changed".
    Stage 2 -- link targets: for lines whose visible text is unchanged, compare
    the URLs attached to them. This is the ONLY way a refreshed Georgia Access
    PUF is visible, since its visible text is static prose.
    """
    a_raw, b_raw = norm_lines(prev_text), norm_lines(curr_text)
    a_disp = [strip_urls(x) for x in a_raw]
    b_disp = [strip_urls(x) for x in b_raw]

    sm = difflib.SequenceMatcher(None, a_disp, b_disp, autojunk=False)
    removed, added = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "delete"):
            removed.extend(x for x in a_disp[i1:i2] if x)
        if tag in ("replace", "insert"):
            added.extend(x for x in b_disp[j1:j2] if x)

    # Stage 2: only over visible lines common to both sides.
    a_links: dict[str, Counter] = defaultdict(Counter)
    b_links: dict[str, Counter] = defaultdict(Counter)
    for disp, raw in zip(a_disp, a_raw):
        a_links[disp].update(urls_in(raw))
    for disp, raw in zip(b_disp, b_raw):
        b_links[disp].update(urls_in(raw))

    link_changes = []
    for disp in set(a_links) & set(b_links):
        if not disp:
            continue
        gone = a_links[disp] - b_links[disp]
        new = b_links[disp] - a_links[disp]
        if not gone and not new:
            continue
        link_changes.append({
            "text": disp,
            "from": [url_tail(u) for u in sorted(gone)],
            "to": [url_tail(u) for u in sorted(new)],
        })
    link_changes.sort(key=lambda c: c["text"])

    return {
        "removed": removed,
        "added": added,
        "link_changes": link_changes,
        "lines_before": len(a_raw),
        "lines_after": len(b_raw),
    }


def unified(prev_text: str, curr_text: str, label_a: str, label_b: str) -> str:
    return "\n".join(difflib.unified_diff(
        norm_lines(prev_text), norm_lines(curr_text),
        fromfile=label_a, tofile=label_b, lineterm="", n=1,
    ))


# --------------------------------------------------------------------------
# health
# --------------------------------------------------------------------------

def health_report(watches: list[dict], now: float, brotli_skipped: dict | None = None) -> list[str]:
    problems = []

    if brotli_skipped and brotli_skipped["snapshots"]:
        n = brotli_skipped["snapshots"]
        m = len(brotli_skipped["watches"])
        detail = f" -- pip said: {_BROTLI_INSTALL_ERROR}" if _BROTLI_INSTALL_ERROR else ""
        problems.append(
            f"**brotli unavailable this run** -- {n} snapshot(s) across {m} "
            f"watch(es) could not be decompressed and were skipped.{detail}"
        )

    checks = [w["last_checked"] for w in watches if w["last_checked"]]
    newest = max(checks) if checks else 0

    if not newest:
        problems.append("**No watch has ever recorded a check.** The datastore looks empty or unreadable.")
    elif (now - newest) > STALE_HOURS * 3600:
        age = (now - newest) / 3600
        problems.append(
            f"**Datastore is stale.** Newest check across all 22 watches is "
            f"{age:.1f}h old ({fmt(newest)}). The container is probably not running -- "
            f"this is an operational problem, not a quiet day."
        )

    for w in watches:
        tags = []
        if w["last_error"]:
            tags.append(f"last_error: `{w['last_error']}`")
        if w["filter_failures"]:
            tags.append(f"{w['filter_failures']} consecutive filter failures "
                        f"(selector may have stopped matching)")
        if w["status"] and w["status"] != 200:
            tags.append(f"HTTP {w['status']}")
        if w["paused"]:
            tags.append("PAUSED")
        # A watch lagging while others moved on. Note: a watch that hasn't
        # CHANGED in months is fine and is deliberately not flagged here.
        if newest and w["last_checked"] and (newest - w["last_checked"]) > STALE_HOURS * 3600:
            lag = (newest - w["last_checked"]) / 3600
            tags.append(f"last checked {lag:.1f}h behind the others -- individually stuck")
        if tags:
            problems.append(f"**{w['name']}** -- " + "; ".join(tags))
    return problems


def fmt(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def cell(s: str) -> str:
    """Watch page titles routinely contain '|' (e.g. 'MLR | CMS'), which breaks
    a markdown table cell. Escape it."""
    return s.replace("|", "\\|")


def delist(s: str) -> str:
    """Drop the leading list marker so link-change bullets don't double up."""
    return BULLET_RE.sub("", s).strip()


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def load_watches(datastore: Path) -> list[dict]:
    watches = []
    for wj in sorted(datastore.glob("*/watch.json")):
        d = wj.parent
        try:
            w = json.loads(wj.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            print(f"  ! unreadable watch.json in {d.name}: {e}", file=sys.stderr)
            continue
        name = (w.get("title") or w.get("page_title")
                or w.get("url", "")).strip() or d.name
        watches.append({
            "uuid": d.name,
            "dir": d,
            "name": name,
            "url": w.get("url", ""),
            "last_checked": w.get("last_checked") or 0,
            "last_error": w.get("last_error") or "",
            "filter_failures": w.get("consecutive_filter_failures") or 0,
            "status": w.get("last_check_status"),
            "paused": bool(w.get("paused")),
            "selectors": w.get("include_filters") or [],
            "history": history_entries(d),
        })
    return watches


def pending_for(watch: dict, state: dict) -> tuple[list, str]:
    """Snapshots to process, and a note about how we decided."""
    hist = watch["history"]
    if not hist:
        return [], "no history"
    seen = state.get(watch["uuid"])
    if not seen:
        # First ever run without a seed: treat the newest as baseline only.
        return [], "unseeded -- baseline set to newest, nothing reported"

    seen_line = seen.get("line")
    seen_ts = seen.get("ts", 0)
    idx = next((i for i, (_, _, raw) in enumerate(hist) if raw == seen_line), None)
    if idx is not None:
        return hist[idx + 1:], ""
    # Stored line was trimmed away by retention.
    newer = [e for e in hist if e[0] > seen_ts]
    note = ("last-seen snapshot has been trimmed away; fell back to timestamp "
            "comparison, so the oldest item below has no predecessor on disk")
    return newer, note


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--datastore", type=Path, default=DEFAULT_DATASTORE)
    ap.add_argument("--state", type=Path, default=None,
                    help="default: <datastore>/.cowork_seen.json")
    ap.add_argument("--outdir", type=Path, default=None,
                    help="default: <datastore>/diffs")
    ap.add_argument("--date", default=None, help="output folder name, default today")
    ap.add_argument("--seed", action="store_true",
                    help="mark every watch's newest snapshot as seen, write state, exit")
    ap.add_argument("--dry-run", action="store_true",
                    help="process and print, but write no files and do not advance state")
    args = ap.parse_args()

    datastore: Path = args.datastore
    if not datastore.is_dir():
        print(f"FATAL: datastore not found: {datastore}", file=sys.stderr)
        return 2

    state_path = args.state or (datastore / ".cowork_seen.json")
    outroot = args.outdir or (datastore / "diffs")
    run_date = args.date or time.strftime("%Y-%m-%d")
    now = time.time()

    watches = load_watches(datastore)
    if not watches:
        print(f"FATAL: no watches under {datastore}", file=sys.stderr)
        return 2

    state = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"FATAL: state file unreadable ({e}). Refusing to run rather "
                  f"than silently reprocess everything.", file=sys.stderr)
            return 2

    # ---------------- seed mode ----------------
    if args.seed:
        new_state = {}
        for w in watches:
            if w["history"]:
                ts, fname, raw = w["history"][-1]
                new_state[w["uuid"]] = {"ts": ts, "line": raw, "name": w["name"]}
        payload = json.dumps(new_state, indent=2, sort_keys=True) + "\n"
        if args.dry_run:
            print(f"[dry-run] would seed {len(new_state)} watches at {state_path}")
        else:
            state_path.write_text(payload, encoding="utf-8")
            # CLAUDE.md section 5: verify the write landed, do not trust the call.
            check = json.loads(state_path.read_text(encoding="utf-8"))
            assert len(check) == len(new_state), "state file write did not land"
            print(f"Seeded {len(new_state)} watches -> {state_path} (verified)")
        for w in watches:
            if w["history"]:
                print(f"  {w['uuid'][:8]} {fmt(w['history'][-1][0])}  {w['name'][:52]}")
        return 0

    # ---------------- normal run ----------------
    outdir = outroot / run_date
    results = []
    vol = {"run_date": run_date, "generated_at": fmt(now), "snapshots": 0,
           "raw_bytes": 0, "normalized_chars": 0, "packet_chars": 0,
           "watches_with_changes": 0, "watches_total": len(watches)}

    if not args.dry_run:
        outdir.mkdir(parents=True, exist_ok=True)

    brotli_skipped = {"snapshots": 0, "watches": set()}

    for w in watches:
        pending, note = pending_for(w, state)
        if not pending and not note:
            continue
        if not pending:
            if note and "unseeded" in note:
                results.append({"watch": w, "note": note, "items": []})
            continue

        hist = w["history"]
        pos = {raw: i for i, (_, _, raw) in enumerate(hist)}
        items = []
        for ts, fname, raw in pending:
            snap = w["dir"] / fname
            if not snap.exists():
                items.append({"ts": ts, "error": f"snapshot file missing on disk: {fname}"})
                continue
            curr = read_snapshot(snap)
            if not curr and fname.endswith(".br") and brotli is None:
                items.append({"ts": ts, "error": "brotli unavailable, cannot read .txt.br"})
                brotli_skipped["snapshots"] += 1
                brotli_skipped["watches"].add(w["uuid"])
                continue

            i = pos.get(raw)
            prev_text, prev_label = "", "(no predecessor on disk)"
            if i is not None and i > 0:
                pfname = hist[i - 1][1]
                psnap = w["dir"] / pfname
                if psnap.exists():
                    prev_text = read_snapshot(psnap)
                    prev_label = f"{fmt(hist[i-1][0])} {pfname}"

            cmp = compare(prev_text, curr)
            vol["snapshots"] += 1
            vol["raw_bytes"] += snap.stat().st_size
            vol["normalized_chars"] += sum(len(x) for x in norm_lines(curr))

            if not args.dry_run:
                dpath = outdir / f"{w['uuid']}__{ts}.diff"
                header = (f"# {w['name']}\n# watch: {w['url']}\n# uuid: {w['uuid']}\n"
                          f"# detected: {fmt(ts)}  (detection time, not publication)\n"
                          f"# prev: {prev_label}\n# curr: {fmt(ts)} {fname}\n\n")
                dpath.write_text(header + unified(prev_text, curr, prev_label, fname) + "\n",
                                 encoding="utf-8")

            cmp["ts"] = ts
            cmp["baseline"] = (prev_text == "")
            items.append(cmp)

        if items:
            vol["watches_with_changes"] += 1
            results.append({"watch": w, "note": note, "items": items})

    packet = render_packet(results, watches, now, run_date, outdir, state, brotli_skipped)
    vol["packet_chars"] = len(packet)
    vol["packet_est_tokens"] = len(packet) // 4
    vol["raw_est_tokens"] = vol["normalized_chars"] // 4

    if args.dry_run:
        print(packet)
        print("\n---- volume ----")
        print(json.dumps(vol, indent=2))
        return 0

    (outdir / "_packet.md").write_text(packet, encoding="utf-8")
    (outdir / "_volume.json").write_text(json.dumps(vol, indent=2) + "\n", encoding="utf-8")

    # Advance state only after the packet and archive are safely written.
    for r in results:
        w = r["watch"]
        if w["history"]:
            ts, fname, raw = w["history"][-1]
            state[w["uuid"]] = {"ts": ts, "line": raw, "name": w["name"]}
    for w in watches:  # also record watches that had nothing pending
        if w["uuid"] not in state and w["history"]:
            ts, fname, raw = w["history"][-1]
            state[w["uuid"]] = {"ts": ts, "line": raw, "name": w["name"]}
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Verify both writes landed (synced volume -- CLAUDE.md section 5).
    assert (outdir / "_packet.md").read_text(encoding="utf-8") == packet, "packet write did not land"
    json.loads(state_path.read_text(encoding="utf-8"))

    print(f"Wrote {outdir / '_packet.md'} ({len(packet):,} chars, "
          f"~{vol['packet_est_tokens']:,} tokens)")
    print(f"Archived {vol['snapshots']} diffs to {outdir}")
    print(f"State advanced at {state_path}")
    return 0


def render_packet(results, watches, now, run_date, outdir, state, brotli_skipped=None) -> str:
    L = []
    A = L.append
    A(f"# Change detection work packet -- {run_date}")
    A("")
    A(f"Generated {fmt(now)} by `scripts/cd_digest_prep.py`. Deterministic, no LLM.")
    A("")
    A("Timestamps below are **detection** times. The global recheck interval is "
      "3 hours, so publication may be up to that much earlier. Never present a "
      "detection time as a publication date.")
    A("")
    A("URLs have been stripped from the text below on purpose -- link at the "
      "watch level only. Where the *only* change was a link target, it is "
      "reported as a filename change under **Link targets**, which is how a "
      "refreshed PUF is visible at all. Full URL-bearing diffs are archived at "
      f"`{outdir.as_posix()}/<uuid>__<ts>.diff`.")
    A("")

    problems = health_report(watches, now, brotli_skipped)
    A("## Operational status")
    A("")
    if problems:
        for p in problems:
            A(f"- {p}")
        A("")
        A("**Report these at the top of the digest.** On a scheduled run nobody "
          "is looking at the changedetection UI.")
    else:
        A(f"- All {len(watches)} watches checking cleanly. Newest check "
          f"{fmt(max((w['last_checked'] for w in watches), default=0))}.")
        A("- No `last_error`, no filter failures, no individually stuck watches.")
    A("")

    changed = [r for r in results if r["items"]]
    A(f"## Changes to review -- {len(changed)} watch(es)")
    A("")
    if not changed:
        A("No new snapshots since the last run. If operational status above is "
          "clean, write nothing and exit.")
        A("")
        return "\n".join(L)

    for r in sorted(changed, key=lambda r: -len(r["items"])):
        w = r["watch"]
        A(f"### {w['name']}")
        A("")
        A(f"- Watch: {w['url']}")
        A(f"- Diff link (Andrew's machine only): http://127.0.0.1:5000/diff/{w['uuid']}")
        A(f"- Snapshots this run: {len(r['items'])}")
        if w["selectors"]:
            A(f"- Selector: `{', '.join(w['selectors'])}`")
        if r["note"]:
            A(f"- Note: {r['note']}")
        A("")

        for it in r["items"]:
            if "error" in it:
                A(f"**{fmt(it['ts'])}** -- could not read: {it['error']}")
                A("")
                continue
            A(f"**{fmt(it['ts'])}**"
              + ("  _(no predecessor on disk -- treat as first sighting, not a change)_"
                 if it["baseline"] else "")
              + f"  [{it['lines_before']} -> {it['lines_after']} lines]")
            A("")
            for label, rows in (("Added", it["added"]), ("Removed", it["removed"])):
                if not rows:
                    continue
                shown = rows[:MAX_LINES_PER_SIDE]
                A(f"{label} ({len(rows)}):")
                A("")
                for x in shown:
                    A(f"  + {x}" if label == "Added" else f"  - {x}")
                if len(rows) > len(shown):
                    A(f"  ... {len(rows) - len(shown)} more, see the archived diff")
                A("")
            if it["link_changes"]:
                shown = it["link_changes"][:MAX_LINK_CHANGES]
                A(f"Link targets changed ({len(it['link_changes'])}) -- visible text "
                  f"identical, file behind it replaced:")
                A("")
                for c in shown:
                    frm = ", ".join(c["from"]) or "(none)"
                    to = ", ".join(c["to"]) or "(none)"
                    A(f"  * {delist(c['text'])[:110]}: `{frm}` -> `{to}`")
                if len(it["link_changes"]) > len(shown):
                    A(f"  ... {len(it['link_changes']) - len(shown)} more, see the archived diff")
                A("")

    A("## Coverage checklist")
    A("")
    A("Every row below must appear in the digest's `### Coverage` table with a "
      "verdict of noise / no fit / reported. Silence on a change is not permitted.")
    A("")
    A("| Watch | Snapshots | uuid |")
    A("|---|---|---|")
    for r in sorted(changed, key=lambda r: r["watch"]["name"].lower()):
        A(f"| {cell(r['watch']['name'][:60])} | {len(r['items'])} | `{r['watch']['uuid'][:8]}` |")
    A("")
    return "\n".join(L)


if __name__ == "__main__":
    sys.exit(main())
