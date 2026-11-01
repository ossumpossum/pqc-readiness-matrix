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
import ipaddress
import re
import pathlib
import sys
import unicodedata
import urllib.parse

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
# Fixed display order, matching the schema enum. The row census prints every value
# including the zeros: ordering by frequency, or printing only what is present, makes a
# census read as a ranking, which is the trust score this schema exists to refuse.
INDEPENDENCE_VALUES = ("first-party", "derivative", "third-party", "unknown")
# Hosts that cannot carry a citation, by NAME here and by ADDRESS in NOT_CITABLE_NETS and
# _not_citable_address. This is the one part of gap 3 that can be a GATE rather than a
# warning: it needs no network, so link rot and rate limits cannot make it flaky, and it is
# what kills the fabricated row that motivated the #46 changes.
#
# The source is the IANA Special-Use Domain Names registry, NOT RFC 2606 alone, and that is
# also the correct attribution. RFC 2606 section 2 reserves only the four top-level names;
# its section 3 reports that IANA "also currently has" the three second-level names reserved,
# and its section 4 records IANA agreeing to "the four top level domain name reservations
# specified in this document". RFC 6761 UPDATES RFC 2606 and the registry references 6761 for
# all seven. Citing 2606 bare, as the first version of this check did, is the
# outdated-citation pattern this repo exists to complain about.
RESERVED_TLDS = (
    "test", "example", "invalid", "localhost",  # RFC 2606 s2, via RFC 6761
    "local",                                    # RFC 6762
    "onion",                                    # RFC 7686
    "alt",                                      # RFC 9476
    "internal",  # ICANN Board Resolution 2024.07.29.06, 2024-07-29: reserved from
                 # delegation in the root zone. Not in any IETF registry, which makes it the
                 # one entry here a reader cannot check against IANA, hence the citation.
)
# Addresses that `is_global` reports as globally reachable and that still cannot host a
# citation, plus one it only reports correctly on recent interpreters. Each measured.
NOT_CITABLE_NETS = tuple(ipaddress.ip_network(n) for n in (
    "192.88.99.0/24",   # deprecated 6to4 relay anycast, RFC 7526; is_global True
    "5f00::/16",        # SRv6 SIDs; IANA IPv6 registry says Globally Reachable False
    "3fff::/20",        # RFC 9637 IPv6 documentation space. is_global only knows this on
                        # CPython 3.12.7+ and 3.13.1+, so it is listed to make the gate's
                        # verdict independent of the contributor's patch level.
    "2001:db8::/32",    # RFC 3849, listed for the same reason rather than trusting is_global
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",   # RFC 5737
))
RESERVED_DOMAINS = (
    "example.com", "example.net", "example.org",        # RFC 2606 s3, via RFC 6761
    "home.arpa", "service.arpa", "resolver.arpa",       # RFC 8375, RFC 9665, RFC 9462
)


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


def _why_not_citable(kind):
    """The reason text. Split from the check because one message covered both cases and was
    false for most of what triggered it: it said "reserved by RFC 2606", and RFC 2606
    reserves no IP addresses and names none of .internal, .local, .onion, .alt or .arpa."""
    if kind == "address":
        return ("is not an address a reader can fetch: RFC 5737 and RFC 3849 as updated by "
                "RFC 9637 reserve it for documentation, or it is loopback, link-local, "
                "multicast, unspecified, CGNAT or RFC 1918, so it cannot be a citation")
    return ("is reserved for documentation, testing or non-DNS resolution (IANA Special-Use "
            "Domain Names registry, RFC 6761, which updates RFC 2606; plus ICANN Board "
            "Resolution 2024.07.29.06 for .internal), so it cannot be a citation")


def _ipv4_from_literal(host):
    """Parse every IPv4 spelling inet_aton accepts, or None.

    `ipaddress.ip_address()` accepts only the four-part decimal form, so each of
    `3221225985`, `0300.0.2.1`, `0xC0000201` and `127.1` fell straight through the address
    branch while resolving to 192.0.2.1 or 127.0.0.1 through gethostbyname. Measured: a row
    with every source rewritten to `https://3221225985/report` validated with exit 0. curl,
    glibc and the WHATWG URL parser all accept these, so a reader following the citation
    would land on a documentation address.

    1 to 4 parts; each part decimal, 0-prefixed octal or 0x-prefixed hex; the last part
    covers the remaining octets.
    """
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = []
    for p in parts:
        if not p:
            return None
        try:
            if p.lower().startswith("0x"):
                n = int(p, 16)
            elif p.startswith("0") and len(p) > 1:
                n = int(p, 8)
            else:
                n = int(p, 10)
        except ValueError:
            return None
        if n < 0:
            return None
        nums.append(n)
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (4 - (len(nums) - 1)):
        return None
    value = nums[-1]
    for i, n in enumerate(nums[:-1]):
        value += n << (8 * (3 - i))
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _not_citable_address(host):
    """The address, if `host` is an IP literal a reader could not fetch. Otherwise None."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = _ipv4_from_literal(host)
    if ip is None:
        return None
    # `is_global` alone is not the test. It reports True for multicast, for 5f00::/16 and
    # for 192.88.99.0/24, and it only knows 3fff::/20 on recent patch levels, so the
    # explicit list carries what it misses and what it learned late.
    if (not ip.is_global) or ip.is_multicast or ip.is_unspecified:
        return ip
    if any(ip in net for net in NOT_CITABLE_NETS):
        return ip
    return None


def reserved_name(url):
    """The host of `url`, if it cannot host a real citation. Otherwise None.

    Returns a (kind, host) pair so the caller can say WHY, because one message covering
    both cases was false for most of what triggered it: it said "reserved by RFC 2606",
    and RFC 2606 reserves no IP addresses and does not mention .internal, .local, .onion,
    .alt or any .arpa name.

    Every case handled here was a measured bypass of an earlier version of this function,
    not a hypothetical:

    - `[^/?#:]+` kept the userinfo, so `https://ref@example.com/report` compared
      "ref@example.com" against the list and matched nothing.
    - `partition(":")` on a bracketed IPv6 authority yielded a host of "[".
    - Percent-encoding, `%65xample.com`.
    - An IP literal bypassed the name list entirely, `https://192.0.2.1/report`.
    - Then the alternate IPv4 spellings bypassed the address branch, because
      `ipaddress.ip_address()` accepts only one of them. See `_ipv4_from_literal`.
    - A fullwidth U+FF45 in `example.com` mapped to `example.com` under IDNA. NFKC caught
      that one and NOT U+3002 or U+FF61, which are label separators with no compatibility
      decomposition to ".", so ToASCII does the normalising now.
    """
    m = re.match(r"^https://([^/?#]*)", str(url))
    if not m:
        return None
    authority = m.group(1).rpartition("@")[2]
    bracket = re.match(r"^\[([^\]]*)\]", authority)
    host = bracket.group(1) if bracket else authority.partition(":")[0]
    host = urllib.parse.unquote(host).strip().rstrip(".").lower()
    if not host:
        return None

    # IDNA ToASCII folds the label separators and the fullwidth forms. It rejects some
    # hosts outright (over-long labels, disallowed characters), so a failure falls back to
    # NFKC rather than letting the host through unnormalised.
    try:
        host = host.encode("idna").decode("ascii").rstrip(".").lower()
    except (UnicodeError, ValueError):
        host = unicodedata.normalize("NFKC", host).rstrip(".").lower()

    ip = _not_citable_address(host)
    if ip is not None:
        return ("address", f"{host} ({ip})" if str(ip) != host else host)
    if host in RESERVED_DOMAINS or any(host.endswith("." + d) for d in RESERVED_DOMAINS):
        return ("name", host)
    if host.rsplit(".", 1)[-1] in RESERVED_TLDS:
        return ("name", host)
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


def supporting_evidence(axis, axis_obj):
    """The evidence blocks that EARN this axis's status, not every block under it.

    Counting every block let one unrelated source speak for a claim it does not support.
    Measured in review: adding a third-party test report to an implementation whose
    `default_enabled` is "no" cleared the warning on a `default-on` status still earned
    entirely by two first-party sources, and a third-party report that a pair FAILED cleared
    it on a `pairwise` status. The second is this gate's own multi-vendor defect one rule over:
    there, vendors are counted only from pairs with `result == "interoperates"`, and the same
    filter belongs here.
    """
    status = axis_obj.get("status")
    if axis in ("standardisation", "failure_mode"):
        ev = axis_obj.get("evidence")
        return [ev] if isinstance(ev, dict) else []
    if axis == "implementation":
        impls = axis_obj.get("implementations", [])
        if status == "default-on":
            impls = [i for i in impls if i.get("default_enabled") == "yes"]
        elif status == "reverted":
            impls = [i for i in impls if i.get("withdrawn_in_version")]
        return [i["evidence"] for i in impls if isinstance(i.get("evidence"), dict)]
    if axis == "interoperability":
        pairs = axis_obj.get("tested_pairs", [])
        if status in ("pairwise", "multi-vendor"):
            pairs = [p for p in pairs if p.get("result") == "interoperates"]
        return [p["evidence"] for p in pairs if isinstance(p.get("evidence"), dict)]
    return list(walk_evidence(axis_obj))


def axis_independence(axis, axis_obj):
    """The set of independence values on the evidence that earns this axis's status."""
    return {ev.get("independence") for ev in supporting_evidence(axis, axis_obj)
            if ev.get("independence")}


def axis_provenance(axis, axis_obj):
    """The independence values earning this axis's status, for display beside it.

    Printed rather than scored. It rides on the status line specifically so the field
    cannot go decorative again: a reader cannot see `default-on` without also seeing whose
    word it rests on, and no arrangement of values makes the line read as better or worse.
    """
    if not axis_obj or axis_obj.get("status") == FLOOR.get(axis):
        return "-"
    kinds = axis_independence(axis, axis_obj)
    return "+".join(sorted(kinds)) if kinds else "no-evidence"


def independence_census(blocks):
    """Counts per value in schema order, including zeros, plus the three property counts.

    Three separate properties, per @leprecha1 on issue #46: provenance (the independence
    values), methodological reproducibility (`reproduction`) and independent verification
    (`verification`). They are counted and nothing else. None of them moves a verdict,
    because nothing available offline can check any of them.
    """
    counts = {k: 0 for k in INDEPENDENCE_VALUES}
    for ev in blocks:
        k = ev.get("independence", "?")
        counts[k] = counts.get(k, 0) + 1
    repro = sum(1 for ev in blocks if ev.get("reproduction"))
    verif = sum(1 for ev in blocks if isinstance(ev.get("verification"), dict))
    n = len(blocks)
    return (" ".join(f"{k}:{v}" for k, v in counts.items())
            + f" repro={repro}/{n} verified={verif}/{n}")


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
        # The NESTED dates get the same parse. Caught by its own test on 2026-11-01: this
        # loop read only the block's own verified_on, so verification.verified_on could be
        # 2026-02-30 and pass, because the schema pattern admits an impossible date on
        # purpose and this is the only thing that rejects one. Any date added to an evidence
        # block in future needs a line here, which is the argument for keeping them few.
        for sub in ("verification", "disputed"):
            obj = ev.get(sub)
            if not isinstance(obj, dict):
                continue
            key = "verified_on" if sub == "verification" else "raised_on"
            raw2 = obj.get(key)
            if raw2 is None:
                continue
            d2 = parse_date(raw2)
            if d2 is None:
                errs.append(f"{sub}.{key} {raw2!r} matches the date pattern but is not a "
                            f"real date")
            elif (d2 - today).days > FUTURE_GRACE_DAYS:
                errs.append(f"{sub}.{key} {raw2} is more than {FUTURE_GRACE_DAYS} day in "
                            f"the future")
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

    # --- a citation cannot live on a host a reader could not fetch ---
    # The fabricated row that motivated the #46 changes cited https://example.invalid/... on
    # all four axes and passed with exit 0, and in the first round it recovered that pass for
    # one character of basis text. Two later versions of this check were each bypassed, by
    # userinfo and then by alternate IPv4 literal spellings, so see reserved_name for what is
    # measured rather than assumed. A hard failure, and it needs no network, which is what
    # makes it a gate rather than a warning.
    for ev in walk_evidence(entry):
        bad = reserved_name(ev.get("source"))
        if bad:
            errs.append(f"evidence source host {bad[1]!r} {_why_not_citable(bad[0])}")
    for doc in axes.get("standardisation", {}).get("documents", []):
        bad = reserved_name(doc.get("url"))
        if bad:
            errs.append(f"document {doc.get('id')} url host {bad[1]!r} "
                        f"{_why_not_citable(bad[0])}")

    # --- NOT HERE: any warning keyed to WHICH independence value an author chose ---
    # Two were tried and both were removed, because each rewarded the lie it was meant to
    # expose. 40f737f warned when an axis rested only on weak evidence: an honest row
    # warned and a row that typed `third-party` over the same URLs did not. Adding a
    # uniformity warning fixed that for a uniform lie and immediately rewarded a fabricated
    # MIX, which the honest exemplar does not have. Offline, nothing here can tell a true
    # `third-party` label from a false one, so every such rule grades the author's typing.
    # That is the thing @leprecha1 asked to be ruled out on issue #46, and the answer is to
    # stop grading rather than to pick a better counterweight.
    #
    # The field is still read, and harder than before. It is mandatory, it must carry a
    # justifying sentence on every value, and `axis_provenance` prints it next to the
    # status it supports on every row, pass or fail. That is what surfaced two mislabels in
    # this repo's own exemplar, where RFC 10024 was `third-party` evidence that RFC 10024 is
    # published. Everything that still warns or fails here is an ABSENCE -- a missing
    # basis, no document carrying a publication date, an unevidenced exposure, a reserved
    # host, a breached TTL -- and an author cannot relabel their way out of an absence.

    # --- a recorded dispute is printed, which is the point of recording it ---
    # Gap 5 said a reader who disagrees with a cell has nowhere in the data to say so.
    # Printing provenance made a cell visible; it did not make it contestable. @leprecha1's
    # mechanism on issue #46 is lighter than anything proposed here before: link the
    # disputed evidence to an issue and let the disagreement travel with the row.
    #
    # It does NOT fail the row. The gate does not adjudicate, and a disputed cell may well
    # be correct. It also cannot be gamed, because a dispute makes a row noisier: nothing
    # here rewards adding a false one.
    for ev in walk_evidence(entry):
        d = ev.get("disputed")
        if isinstance(d, dict):
            warns.append(f"DISPUTED: {d.get('note')} [{d.get('url')}]")

    # --- an exposure with no evidence is the free-text column this schema objects to ---
    # Version 2 could not express one: known_exposures items set additionalProperties:false
    # with no evidence property, so all five on the exemplar were unevidenced by contract.
    for i, exp in enumerate(axes.get("failure_mode", {}).get("known_exposures", [])):
        if not isinstance(exp.get("evidence"), dict):
            warns.append(f"failure_mode: known_exposure {i} ({exp.get('class')}) carries no "
                         f"evidence, so it is an assertion in a structured field")

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

        # Printed on BOTH branches. It was in the pass branch only, which withheld it from
        # the one reader who needs it most: whoever is fixing the row. A census, not a score:
        # every value in schema order including the zeros, because printing only what is
        # present and sorting it alphabetically made `independently-reproducible:4` read as a
        # top mark. Row-level rather than per-axis, since a single trust number for a row is
        # the thing this schema exists to refuse and the per-axis picture is in the warnings.
        mix = independence_census(list(walk_evidence(entry)))

        # Built BEFORE the branch, because the README claims the provenance is printed next to
        # the status it supports "on every row, pass or fail" and it was in the pass branch
        # only. A failing row printed the census and no provenance at all, which is the branch
        # where a reader needs it most: the same defect as the census one commit earlier, in
        # the line added to fix that one.
        ages = []
        for axis in TTL_DAYS:
            d = axis_evidence_dates(entry.get("axes", {}).get(axis, {}))
            if d:
                ages.append((today - min(d)).days)
        summary = " ".join(
            f"{a[:6]}={entry.get('axes', {}).get(a, {}).get('status', '?')}"
            f"/{axis_provenance(a, entry.get('axes', {}).get(a))}" for a in TTL_DAYS)
        age = f"{max(ages)}d" if ages else "n/a"

        if errs:
            failed += 1
            print(f"FAIL {f.name}  oldest_evidence={age}  {summary}  indep={mix}")
            for e in errs:
                print(f"    {e}")
        else:
            print(f"ok   {f.name}  oldest_evidence={age}  {summary}  indep={mix}")
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
