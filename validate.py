#!/usr/bin/env python3
"""Validate the PQC readiness matrix: schema, semantics, and cross-file consistency.

Run:  python3 validate.py [protocols_dir]
Exit: 0 all entries valid, 1 any failure, 2 the gate itself could not run.

VERSION 2. An adversarial review of version 1 passed 5 of 6 deliberately false
rows, crashed on a schema-valid date and silently skipped every row after it, and
reported success with exit 0 when jsonschema was not importable. Each of those is
addressed here, and each has a committed fixture in tests/ so it cannot regress.

THE CENTRAL CHANGE: last_verified is no longer an authored field.

In version 1 a contributor wrote last_verified by hand and the only staleness
check read that field, so the cheapest way to pass was to bump one date and
re-verify nothing. The gate rewarded the behaviour it existed to prevent. Here
the effective verification date of an axis is DERIVED as the oldest verified_on
among the evidence supporting it. Freshness cannot be asserted, only evidenced.
That also removes a contradiction in version 1, where the schema promised claims
"may carry their own, more recent, verified_on" and the gate rejected exactly
that.

PER-AXIS TTLs, because one global TTL is wrong in both directions: an RFC number
does not rot in 180 days, and a default-on claim can rot in two weeks.
"""
import datetime as dt
import json
import re
import pathlib
import sys

TTL_DAYS = {
    "standardisation": 365,
    "implementation": 90,
    "interoperability": 180,
    "failure_mode": 180,
}
FUTURE_GRACE_DAYS = 1  # contributors at UTC+8..+14 date rows in local time
# How long a row may sit unowned past its TTL before the gate stops tolerating it.
NEEDS_OWNER_GRACE_DAYS = 30
HERE = pathlib.Path(__file__).parent
FLOOR = {
    "standardisation": "none",
    "implementation": "none",
    "interoperability": "not_assessed",
    "failure_mode": "not_assessed",
}
# Standardisation statuses that assert the standards work has concluded. The schema already
# requires a cited document for each of these; check_entry additionally requires one of those
# documents to carry a real publication date, so the "document newer than the evidence" clock
# cannot be switched off by omitting a field.
STANDARDISATION_SETTLED = ("approved", "published", "superseded", "deprecated", "withdrawn")


def die(msg):
    print(f"GATE ERROR: {msg}", file=sys.stderr)
    raise SystemExit(2)


def load_validator():
    """Fail closed. Version 1 degraded to a subset of itself and printed success."""
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        die("jsonschema is required. pip install -r requirements.txt")
    schema_path = HERE / "pqc-readiness.schema.json"
    if not schema_path.exists():
        die(f"schema not found at {schema_path}")
    return Draft202012Validator(json.loads(schema_path.read_text()))


def parse_date(s):
    """Return a date or None. The schema pattern admits 2026-02-30; this catches it."""
    try:
        return dt.date.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def walk_evidence(node):
    if isinstance(node, dict):
        if "verified_on" in node and "source_kind" in node:
            yield node
        for v in node.values():
            yield from walk_evidence(v)
    elif isinstance(node, list):
        for v in node:
            yield from walk_evidence(v)


def axis_evidence_dates(axis_obj):
    out = []
    for ev in walk_evidence(axis_obj):
        d = parse_date(ev.get("verified_on"))
        if d:
            out.append(d)
    return out


def check_entry(entry, today, top10):
    """Semantic rules a JSON Schema cannot express. Never raises."""
    errs, warns = [], []
    axes = entry.get("axes", {})

    # --- dates are real, and not from the future ---
    for ev in walk_evidence(entry):
        raw = ev.get("verified_on")
        d = parse_date(raw)
        if d is None:
            errs.append(f"evidence verified_on {raw!r} matches the date pattern but is not a real date")
        elif (d - today).days > FUTURE_GRACE_DAYS:
            errs.append(f"evidence verified_on {raw} is more than {FUTURE_GRACE_DAYS} day in the future")
    for doc in axes.get("standardisation", {}).get("documents", []):
        if doc.get("published") and parse_date(doc["published"]) is None:
            errs.append(f"document {doc.get('id')} published {doc['published']!r} is not a real date")

    # --- derived freshness, per axis ---
    for axis, ttl in TTL_DAYS.items():
        obj = axes.get(axis)
        if not obj:
            continue
        if obj.get("status") == FLOOR[axis]:
            continue  # a floor status asserts nothing, so nothing to keep fresh
        dates = axis_evidence_dates(obj)
        if not dates:
            errs.append(f"{axis}: status {obj.get('status')!r} is above the floor but no evidence "
                        f"carries a verified_on")
            continue
        oldest = min(dates)
        age = (today - oldest).days
        if age > ttl:
            msg = f"{axis}: oldest supporting evidence is {oldest} ({age} days old, TTL {ttl})"
            # needs-owner downgrades a breach so an orphaned row is visible rather than
            # blocking the build, but it is BOUNDED: past TTL + GRACE it fails anyway.
            # Unbounded, it was a one-word permanent opt-out from the only staleness
            # check here, which is the v1 defect in different clothing.
            if entry.get("row_state") == "needs-owner" and age <= ttl + NEEDS_OWNER_GRACE_DAYS:
                warns.append(msg + " [needs-owner, reported not failed]")
            else:
                if entry.get("row_state") == "needs-owner":
                    msg += (f" [needs-owner, but past TTL+{NEEDS_OWNER_GRACE_DAYS}d grace, "
                            f"so it fails: an unowned row cannot stay green forever]")
                errs.append(msg)

    std = axes.get("standardisation", {})

    # --- a row claiming the standards work is done must give the clock something to read ---
    # Without this the rule below has no teeth. `published` is OPTIONAL on five of the ten
    # document statuses, so a row could claim standardisation: published, cite a document
    # carrying no publication date, and the external clock would simply not exist. Measured
    # in review on 2026-10-30: such a row passed with exit 0 while citing a document that
    # does not exist and resting on 301-day-old evidence. The point of the next rule is that
    # one date in the comparison is outside the author's control, which is only true if that
    # date is required to be there.
    if std.get("status") in STANDARDISATION_SETTLED:
        docs = std.get("documents", [])
        if not any(parse_date(d.get("published") or "") for d in docs):
            errs.append(f"standardisation: status {std.get('status')!r} requires at least one cited "
                        f"document with a real `published` date; none of the {len(docs)} cited "
                        f"document(s) carries one")

    # --- a cited document published after the row's own evidence means the row is stale ---
    std_dates = axis_evidence_dates(std)
    if std_dates:
        newest_doc, newest = None, None
        for doc in std.get("documents", []):
            p = parse_date(doc.get("published") or "")
            if p and (newest is None or p > newest):
                newest_doc, newest = doc.get("id"), p
        if newest and min(std_dates) < newest:
            errs.append(f"standardisation: {newest_doc} published {newest} after the oldest supporting "
                        f"evidence ({min(std_dates)}); the row needs re-verification, not a date bump")

    # --- supersession consistency: what rule 3 was reaching for ---
    for doc in std.get("documents", []):
        if doc.get("superseded_by") and std.get("status") not in ("superseded", "deprecated", "withdrawn"):
            errs.append(f"document {doc.get('id')} has superseded_by but standardisation.status is "
                        f"{std.get('status')!r}")

    # --- status must be earned by its own contents ---
    impl = axes.get("implementation", {})
    impls = impl.get("implementations", [])
    if impl.get("status") == "default-on" and not any(i.get("default_enabled") == "yes" for i in impls):
        errs.append("implementation.status 'default-on' but no implementation has default_enabled 'yes'")
    if impl.get("status") == "reverted" and not any(i.get("withdrawn_in_version") for i in impls):
        errs.append("implementation.status 'reverted' but no implementation records withdrawn_in_version")
    seen = {}
    for i in impls:
        key = str(i.get("name", "")).strip().lower()
        if key in seen and seen[key] != i.get("default_enabled"):
            errs.append(f"implementation {i.get('name')!r} appears twice with conflicting default_enabled")
        seen[key] = i.get("default_enabled")

    interop = axes.get("interoperability", {})
    pairs = interop.get("tested_pairs", [])
    if interop.get("status") in ("pairwise", "multi-vendor"):
        if not any(p.get("result") == "interoperates" for p in pairs):
            errs.append(f"interoperability.status {interop['status']!r} but no recorded pair interoperates")
        if interop["status"] == "multi-vendor":
            # Count vendors only from pairs that INTEROPERATE. Counting every pair let a third
            # stack earn 'multi-vendor' by appearing in a pair that failed, which is the
            # opposite of what the status asserts: one working pair plus one broken pair is a
            # two-stack result with a known incompatibility, not three-way interop.
            vendors = {str(v).strip().lower()
                       for p in pairs if p.get("result") == "interoperates"
                       for v in (p.get("a", ""), p.get("b", ""))}
            vendors.discard("")
            if len(vendors) < 3:
                errs.append(f"interoperability.status 'multi-vendor' but only {len(vendors)} distinct "
                            f"stacks appear in pairs that interoperate")

    # --- interop pairs should name implementations the row actually lists ---
    known = {str(i.get("name", "")).strip().lower() for i in impls}
    known.discard("")
    for p in pairs:
        for side in ("a", "b"):
            v = str(p.get(side, "")).strip().lower()
            if known and v and v not in known:
                warns.append(f"interoperability pair names {p.get(side)!r}, not in implementations")

    # --- related entries exist ---
    for q in entry.get("related_owasp_entries", []):
        if q not in top10:
            errs.append(f"related_owasp_entries {q} is not in the Top 10 manifest")

    return errs, warns


def main():
    validator = load_validator()
    pdir = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "protocols"
    if not pdir.is_dir():
        die(f"{pdir} is not a directory")

    # Fails CLOSED. An absent or empty manifest previously yielded an empty set, and the
    # check below was guarded on `if top10`, so deleting this file made every
    # related_owasp_entries value pass silently: a row citing QS99 validated with exit 0.
    # That is the same fail-open shape this gate exists to remove, one dependency over.
    man = HERE / "top10.json"
    if not man.exists():
        die(f"{man} is missing; refusing to validate related_owasp_entries against nothing")
    try:
        top10 = {e["id"] for e in json.loads(man.read_text())["entries"]}
    except Exception as e:
        die(f"top10.json present but unreadable: {e}")
    if not top10:
        die("top10.json contains no entries; refusing to run with an empty manifest")

    # recursive and case-insensitive; version 1 reported "no entries found" for a
    # directory containing protocols/STALE.JSON and protocols/nested/ssh.json
    all_files = [p for p in pdir.rglob("*") if p.is_file()]
    files = sorted(p for p in all_files if p.suffix.lower() == ".json")
    skipped = [p for p in all_files if p.suffix.lower() != ".json"]
    if not files:
        print(f"FAIL: no entries found in {pdir}")
        return 1

    failed = 0
    seen_slug, seen_pair = {}, {}
    today = dt.datetime.now(dt.timezone.utc).date()

    for f in files:
        errs, warns = [], []
        try:
            entry = json.loads(f.read_text())
        except json.JSONDecodeError as e:
            print(f"FAIL {f.name}: not valid JSON at line {e.lineno} col {e.colno}: {e.msg}")
            failed += 1
            continue

        schema_errs = sorted(validator.iter_errors(entry), key=lambda e: list(e.path))
        for e in schema_errs:
            loc = "/".join(str(p) for p in e.path) or "(root)"
            errs.append(f"schema: {loc}: {e.message}")

        # Only run semantics on schema-valid input, and never let them abort the run.
        # Version 1 ran them regardless, so a document missing 'id' raised KeyError
        # and hid every subsequent file.
        if not schema_errs:
            try:
                e2, w2 = check_entry(entry, today, top10)
                errs += e2
                warns += w2
            except Exception as exc:
                errs.append(f"internal check error ({type(exc).__name__}: {exc})")

        slug = entry.get("slug")
        if isinstance(slug, str) and slug:
            if slug != f.stem:
                errs.append(f"slug {slug!r} does not match filename stem {f.stem!r}")
            if slug in seen_slug:
                errs.append(f"slug {slug!r} already used by {seen_slug[slug]}")
            seen_slug[slug] = f.name
        # Normalised to alphanumerics: protocol is free text, so .strip().lower() alone let
        # "TLS1.3" and "TLS 1.3" count as different protocols and two contradictory rows for
        # the same protocol-and-class both passed. tests/test_gate.py relied on that gap to
        # isolate the slug case, which is how it survived.
        pkey = re.sub(r"[^a-z0-9]", "", str(entry.get("protocol", "")).lower())
        pair = (pkey, entry.get("mechanism_class"))
        if all(pair):
            if pair in seen_pair:
                errs.append(f"protocol/mechanism_class {pair} already covered by {seen_pair[pair]}")
            seen_pair[pair] = f.name

        if errs:
            failed += 1
            print(f"FAIL {f.name}")
            for e in errs:
                print(f"    {e}")
        else:
            ages, summary = [], ""
            for axis in TTL_DAYS:
                d = axis_evidence_dates(entry.get("axes", {}).get(axis, {}))
                if d:
                    ages.append((today - min(d)).days)
            summary = " ".join(
                f"{a[:6]}={entry.get('axes', {}).get(a, {}).get('status', '?')}" for a in TTL_DAYS)
            print(f"ok   {f.name}  oldest_evidence={max(ages) if ages else 'n/a'}d  {summary}")
        for w in warns:
            print(f"     warn: {w}")

    for p in skipped:
        print(f"FAIL {p.relative_to(pdir)}: under protocols/ but not a .json entry; a renderer may read it")
        failed += 1

    print()
    valid = len(files) - min(failed, len(files))
    print(f"{valid} of {len(files)} entries valid" + (f", {len(skipped)} stray file(s)" if skipped else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
