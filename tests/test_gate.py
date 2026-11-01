#!/usr/bin/env python3
"""Regression suite for the readiness gate.

Every MUST_FAIL case below is an attack that passed version 1 of this gate. The
suite exists because version 1's central argument was "the gate catches it" while
5 of 6 deliberately false rows validated with exit 0, and there was no test to
notice. A gate without a suite is an assertion.

Run:  python3 tests/test_gate.py
Exit: 0 all cases behave as specified, 1 otherwise.
"""
import copy
import datetime as dt
import re
import json
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).parent
ROOT = HERE.parent
_LIVE = json.loads((ROOT / "protocols" / "tls-1-3-key-establishment.json").read_text())

# The suite must not expire. Using the live row verbatim meant its 90d implementation TTL
# would fail this file in January, turning a required check red on every unrelated PR for a
# reason that has nothing to do with the change under review: a self-inflicted outage in
# somebody else's repo. So the suite tests the row's STRUCTURE with its implementation dates
# refreshed, and `validate.py protocols` is the part that is allowed to go red when the real
# data goes stale, which is the whole point of the TTLs.
GOOD = copy.deepcopy(_LIVE)


def _refresh_implementation_dates(row):
    today = dt.date.today().isoformat()
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "verified_on":
                    o[k] = today
                else:
                    walk(v)
        elif isinstance(o, list):
            for i in o:
                walk(i)
    walk(row.get("axes", {}).get("implementation", {}))
    return row


_refresh_implementation_dates(GOOD)


def _all_evidence(node):
    """Every evidence object in a row. They nest per axis AND per implementation, so a
    top-level loop reaches two of the four and a probe can look like a pass."""
    if isinstance(node, dict):
        if "source_kind" in node and "independence" in node:
            yield node
        for v in node.values():
            yield from _all_evidence(v)
    elif isinstance(node, list):
        for v in node:
            yield from _all_evidence(v)


# Fixtures cite a host that is deliberately NOT reserved and NOT an address, because the gate
# rejects both and a fixture under example.test would fail for a reason unrelated to the case
# under test. Nothing fetches it. The reserved hosts get their own cases below.
FIXTURE_HOST = "https://sources.pqcm-fixture.org"


def fixture_evidence(**over):
    """A complete, schema-valid evidence block for fixtures to vary one field of.

    Seven fixtures hand-rolled this dict. When `independence_basis` became mandatory on
    every value, three of them silently became invalid for that reason instead of testing
    what they claimed, and the suite reported them as broken rather than as vacuous only
    because the expected outcome happened to be acceptance. One constructor means the next
    required field breaks every fixture at once, loudly, in one place.
    """
    ev = {
        "source_kind": "test-report",
        "independence": "third-party",
        "independence_basis": "Fixture. Stands in for a disinterested report.",
        "source": FIXTURE_HOST + "/r",
        "verified_on": dt.date.today().isoformat(),
    }
    ev.update(over)
    return ev


def mutate(fn):
    e = copy.deepcopy(GOOD)
    fn(e)
    return e


def doc_by_id(e, prefix):
    """The cited document whose id starts with `prefix`. Raises if absent or ambiguous.

    Fixtures used to index `documents[0]` and `documents[2]`. Adding RFC 9846 to the row
    shifted both: one fixture went red, and three kept passing while mutating a different
    document than the one they are named after. A fixture that silently changes its own
    subject is worse than one that breaks, so this raises rather than returning None.
    """
    hits = [d for d in e["axes"]["standardisation"]["documents"]
            if str(d.get("id", "")).startswith(prefix)]
    if len(hits) != 1:
        raise AssertionError(f"expected exactly 1 cited document starting {prefix!r}, "
                             f"found {len(hits)}")
    return hits[0]


def no_documents(e):
    e["axes"]["standardisation"] = {"status": "published", "documents": []}


def blank_implementation(e):
    e["axes"]["implementation"] = {
        "status": "default-on",
        "implementations": [{
            "name": "  ", "version": "1", "default_enabled": "yes", "algorithms": ["x"],
            "evidence": fixture_evidence(source_kind="release-notes",
                                         independence="first-party")}]}


def default_on_unsupported(e):
    for i in e["axes"]["implementation"]["implementations"]:
        i["default_enabled"] = "no"


def ancient_evidence(e):
    for i in e["axes"]["implementation"]["implementations"]:
        i["evidence"]["verified_on"] = "1970-01-01"


def impossible_date(e):
    e["axes"]["failure_mode"]["evidence"]["verified_on"] = "2026-02-30"


def future_date(e):
    e["axes"]["failure_mode"]["evidence"]["verified_on"] = "2030-01-01"


def version_latest(e):
    e["axes"]["implementation"]["implementations"][0]["version"] = "latest"


def insecure_source(e):
    e["axes"]["failure_mode"]["evidence"]["source"] = "javascript:alert(1)"


def empty_source(e):
    e["axes"]["failure_mode"]["evidence"]["source"] = ""


def excerpt_without_verbatim(e):
    e["axes"]["failure_mode"]["evidence"].pop("verbatim")


def bogus_related(e):
    e["related_owasp_entries"] = ["QS99"]


def multi_vendor_all_fail(e):
    e["axes"]["interoperability"] = {
        "status": "multi-vendor",
        "tested_pairs": [{"a": "OpenSSL", "b": "Go crypto/tls", "result": "fails",
                          "evidence": fixture_evidence()}]}


def multi_vendor_third_stack_only_fails(e):
    """Two stacks interoperate, a third appears only in a pair that FAILS.

    Found in adversarial review on 2026-10-30: the vendor count was taken from every
    recorded pair regardless of result, so a third stack earned 'multi-vendor' by failing.
    That is a two-stack result with a known incompatibility, which is the opposite of what
    the status asserts. multi-vendor-all-pairs-fail does not cover it, because there at
    least one pair does interoperate.
    """
    ev = {"source_kind": "test-report", "independence": "third-party",
          "source": "https://example.test/r", "verified_on": "2026-10-14"}
    e["axes"]["interoperability"] = {
        "status": "multi-vendor",
        "tested_pairs": [
            {"a": "OpenSSL", "b": "Go crypto/tls", "result": "interoperates", "evidence": dict(ev)},
            {"a": "OpenSSL", "b": "wolfSSL", "result": "fails", "evidence": dict(ev)},
        ]}


def pairwise_no_pairs(e):
    e["axes"]["interoperability"] = {"status": "pairwise", "tested_pairs": []}


def failure_mode_no_evidence(e):
    e["axes"]["failure_mode"] = {"status": "conditional"}


def doc_superseded_mismatch(e):
    doc_by_id(e, "RFC 10024")["superseded_by"] = "RFC 99999"


def doc_published_after_evidence(e):
    doc_by_id(e, "RFC 10024")["published"] = "2026-10-20"


def boolean_enum(e):
    e["axes"]["standardisation"]["status"] = False


def wrong_schema_version(e):
    e["schema_version"] = 1


def rfc_without_published(e):
    doc_by_id(e, "RFC 10024").pop("published")


def unversioned_draft(e):
    doc_by_id(e, "draft-ietf-uta-pqc-app")["id"] = "draft-ietf-uta-pqc-app"


def settled_status_with_only_undated_documents(e):
    """Claim the standards work is done while citing nothing that carries a date.

    `published` is optional on five of the ten document statuses, `other` among them, so
    this row satisfies the schema. It was found in adversarial review on 2026-10-30, where
    it passed with exit 0 while citing a document that does not exist and resting on
    301-day-old evidence. Without it the document-newer-than-the-evidence rule can be
    switched off by omitting a field, which makes the claim that one side of that
    comparison is outside the author's control false.
    """
    e["axes"]["standardisation"]["documents"] = [{
        "id": "SP 800-999",
        "title": "Totally Real Standard",
        "status": "other",
        "url": FIXTURE_HOST + "/doc",
    }]


def unknown_independence_without_basis(e):
    """Use the honest value without saying why it could not be established.

    `unknown` was added to the enum after @leprecha1 raised, on issue #46, that a mandatory
    classification with no escape hatch forces an author to assert independence they cannot
    establish. The escape hatch must not be cheaper than the three positive values it exists
    to replace, or it becomes the default and the field means nothing again.
    """
    ev = e["axes"]["standardisation"]["evidence"]
    ev["independence"] = "unknown"
    # Popped explicitly. Setting the value is no longer enough to remove the basis, because
    # the basis became mandatory on every value, so without this the case tested nothing.
    ev.pop("independence_basis", None)


def provenance_maximal_without_basis(e):
    """The strongest value in the enum on every block, asserted and unexplained.

    Measured on 2026-10-31 against the previous gate: this row passed with exit 0 while every
    source was `https://example.invalid/...`, every excerpt was invented and marked
    `verbatim: yes`, and it reported `oldest_evidence=0d` against the real row's 17d, so the
    fabricated row graded as the fresher of the two. `independently-reproducible` now costs a
    sentence naming what to re-run.

    What this case does NOT prove: the same row under a host the gate cannot rule out, with
    a plausible basis string, still passes, because nothing fetches `source`. That is gap 3,
    it is tested below as `plausible-host-fabrication-still-passes`, and it is the only thing
    that would turn provenance into verification.
    """
    for ev in _all_evidence(e):
        ev["independence"] = "third-party"
        ev.pop("independence_basis", None)
        ev["source"] = FIXTURE_HOST + "/pqc/does-not-exist"
        ev["excerpt"] = "This document confirms the mechanism is fully deployed and interoperable."
        ev["verbatim"] = "yes"


def reserved_source_host(host):
    """A host that cannot carry a citation, by name or by address.

    The fabricated row that drove the whole #46 change cited https://example.invalid/... on
    every axis and passed with exit 0. This is the one part of gap 3 that can be a gate
    rather than a warning: no network, so link rot and rate limits cannot make it flaky.
    Names come from the IANA Special-Use Domain Names registry (RFC 6761, which updates RFC
    2606) plus ICANN Resolution 2024.07.29.06 for .internal; addresses are anything a reader
    could not fetch.
    """
    def fn(e):
        for ev in _all_evidence(e):
            ev["source"] = f"https://{host}/evidence"
    return fn


def reserved_authority(host):
    """Reserved names must be caught through userinfo and percent-encoding.

    Reproduced against dedcbd1 before this existed: the host was taken as `[^/?#:]+`, which
    keeps userinfo, so `https://ref@example.com/report` compared "ref@example.com" against
    the reserved list, matched nothing, and a fully fabricated row passed with exit 0 under a
    name the registry covers. The README called the check a gate on "a source under a
    reserved name" while four families evaded it.
    """
    def fn(e):
        for ev in _all_evidence(e):
            ev["source"] = f"https://{host}/report"
    return fn


def reserved_document_url(e):
    """The same rule has to cover `documents[].url`, which is not an evidence block and so
    is not reached by the evidence walk. Asserted because it was added separately."""
    doc_by_id(e, "RFC 10024")["url"] = "https://standards.invalid/rfc10024"


def removed_enum_value(e):
    """`independently-reproducible` was removed from the enum in the second #46 round.

    It conflated two dimensions: the other three values describe the relation between the
    evidence author and the subject of the claim, while this one described a property of
    method. A vendor's own pinned harness was both, with no precedence rule. Reproducibility
    moved to its own `reproduction` field.
    """
    e["axes"]["standardisation"]["evidence"]["independence"] = "independently-reproducible"


def empty_reproduction(e):
    """`reproduction` is optional, but present-and-blank is not a reproduction recipe."""
    e["axes"]["implementation"]["implementations"][0]["evidence"]["reproduction"] = "  "


def unknown_independence_past_ttl(e):
    """`unknown` must not be an exemption. It describes the evidence, not a floor status.

    The draft comment asserted this and the suite did not check it, which is the pattern the
    comment criticises: a behavioural claim nothing asserts. Raised in review 2026-10-31.
    """
    for ev in _all_evidence(e["axes"]["implementation"]):
        ev["independence"] = "unknown"
        ev["independence_basis"] = "Affiliation not stated in the source."
    set_all_dates(e["axes"]["implementation"],
                  (dt.date.today() - dt.timedelta(days=200)).isoformat())


def whitespace_basis(e):
    """A present-but-empty basis is not a basis. `$defs/nonEmpty` carries a \\S pattern, and
    a `maxLength` sibling of `$ref` only applies under draft 2020-12, which this schema
    declares and the gate pins. Asserted so a loader change to older tooling fails here."""
    ev = e["axes"]["standardisation"]["evidence"]
    ev["independence"] = "unknown"
    ev["independence_basis"] = "   \t  "


def verification_without_attribution(e):
    """An unattributed attestation is what this field exists to replace.

    The whole value of a separate verification field is that somebody's name is on it. If
    `verified_by` were optional, "verified" becomes another unowned label, which is the
    defect the previous two rounds were spent removing.
    """
    ev = e["axes"]["standardisation"]["evidence"]
    ev["verification"] = {"verified_on": "2026-11-01", "method": "re-read the RFC"}


def verification_without_method(e):
    """"Verified" with no stated method is not checkable by the next reader."""
    ev = e["axes"]["standardisation"]["evidence"]
    ev["verification"] = {"verified_by": "someone", "verified_on": "2026-11-01"}


def verification_with_impossible_date(e):
    """The date goes through the same real-date parse as every other date in the row."""
    ev = e["axes"]["standardisation"]["evidence"]
    ev["verification"] = {"verified_by": "someone", "verified_on": "2026-02-30",
                          "method": "re-read the RFC"}


def disputed_without_url(e):
    """A dispute with nowhere to argue it is a complaint, not contestability."""
    ev = e["axes"]["standardisation"]["evidence"]
    ev["disputed"] = {"note": "RFC 10024 is not third-party evidence of its own publication"}


def disputed_with_non_https_url(e):
    ev = e["axes"]["standardisation"]["evidence"]
    ev["disputed"] = {"url": "github.com/OWASP/quantum-security-project/issues/46",
                      "note": "wrong label"}


def disputed_with_blank_note(e):
    ev = e["axes"]["standardisation"]["evidence"]
    ev["disputed"] = {"url": "https://github.com/OWASP/quantum-security-project/issues/46",
                      "note": "   "}


MUST_FAIL = {
    "no-documents-but-published": no_documents,
    "blank-implementation-name": blank_implementation,
    "default-on-nothing-enabled": default_on_unsupported,
    "ancient-evidence-beyond-ttl": ancient_evidence,
    "impossible-date-2026-02-30": impossible_date,
    "future-dated-evidence": future_date,
    "version-latest": version_latest,
    "non-https-source": insecure_source,
    "empty-source": empty_source,
    "excerpt-without-verbatim": excerpt_without_verbatim,
    "related-entry-not-in-manifest": bogus_related,
    "multi-vendor-all-pairs-fail": multi_vendor_all_fail,
    "multi-vendor-third-stack-only-fails": multi_vendor_third_stack_only_fails,
    "pairwise-with-no-pairs": pairwise_no_pairs,
    "failure-mode-without-evidence": failure_mode_no_evidence,
    "superseded-by-status-mismatch": doc_superseded_mismatch,
    "document-published-after-evidence": doc_published_after_evidence,
    "boolean-in-enum": boolean_enum,
    "wrong-schema-version": wrong_schema_version,
    "rfc-without-published-date": rfc_without_published,
    "unversioned-draft-id": unversioned_draft,
    "settled-status-with-only-undated-documents": settled_status_with_only_undated_documents,
    "unknown-independence-without-basis": unknown_independence_without_basis,
    "provenance-maximal-without-basis": provenance_maximal_without_basis,
    "unknown-independence-past-ttl": unknown_independence_past_ttl,
    "whitespace-independence-basis": whitespace_basis,
    "reserved-source-host-invalid": reserved_source_host("example.invalid"),
    "reserved-source-host-test": reserved_source_host("fixtures.test"),
    "reserved-source-host-example-tld": reserved_source_host("docs.example"),
    "reserved-source-host-localhost": reserved_source_host("localhost"),
    "reserved-source-host-example-com": reserved_source_host("www.example.com"),
    "reserved-document-url": reserved_document_url,
    "reserved-host-behind-userinfo": reserved_authority("ref@example.com"),
    "reserved-host-behind-userinfo-and-password": reserved_authority("a:b@www.example.org"),
    "reserved-host-percent-encoded": reserved_authority("%65xample.com"),
    "reserved-host-icann-internal": reserved_authority("evidence.internal"),
    "reserved-host-mdns-local": reserved_authority("sources.local"),
    "reserved-host-onion": reserved_authority("abc.onion"),
    "reserved-host-home-arpa": reserved_authority("host.home.arpa"),
    # An IP literal bypassed the name list entirely. Rewriting every source in the exemplar
    # to https://192.0.2.1/report validated with exit 0, which revived the whole fabricated
    # row attack: RFC 5737 and RFC 3849 reserve documentation ranges that are the IP analogue
    # of example.com. Reproduced 2026-10-31.
    "reserved-host-rfc5737-documentation-ipv4": reserved_authority("192.0.2.1"),
    "reserved-host-rfc5737-second-range": reserved_authority("198.51.100.7"),
    "reserved-host-rfc3849-documentation-ipv6": reserved_authority("[2001:db8::1]"),
    "reserved-host-loopback": reserved_authority("127.0.0.1"),
    # Also a parser bug: partition(":") on a bracketed authority yielded a host of "[".
    "reserved-host-loopback-ipv6-bracketed": reserved_authority("[::1]"),
    "reserved-host-rfc1918": reserved_authority("10.0.0.5"),
    "reserved-host-link-local": reserved_authority("169.254.1.1"),
    # U+FF45 FULLWIDTH LATIN SMALL LETTER E. Maps to example.com under UTS-46, so the name
    # that would actually resolve is reserved; NFKC normalisation is what catches it.
    "reserved-host-fullwidth-idna": reserved_authority("\uff45xample.com"),
    # Alternate IPv4 spellings. ipaddress.ip_address() accepts only the four-part decimal
    # form, so each of these fell through the address branch while resolving to a
    # documentation or loopback address through gethostbyname. Measured 2026-10-31: a row
    # with every source rewritten to https://3221225985/report validated with exit 0.
    "reserved-host-ipv4-decimal-integer": reserved_authority("3221225985"),
    "reserved-host-ipv4-octal": reserved_authority("0300.0.2.1"),
    "reserved-host-ipv4-hex": reserved_authority("0xC0000201"),
    "reserved-host-ipv4-short-form-loopback": reserved_authority("127.1"),
    # Label separators with no compatibility decomposition to ".", so NFKC left them alone
    # while IDNA ToASCII resolves both to example.com.
    "reserved-host-ideographic-full-stop": reserved_authority("example\u3002com"),
    "reserved-host-halfwidth-ideographic-stop": reserved_authority("example\uff61com"),
    # Addresses is_global calls globally reachable that still cannot host a citation.
    "reserved-host-multicast": reserved_authority("224.0.0.251"),
    "reserved-host-multicast-ipv6": reserved_authority("[ff02::1]"),
    "reserved-host-srv6-sid-block": reserved_authority("[5f00::1]"),
    "reserved-host-6to4-relay-anycast": reserved_authority("192.88.99.1"),
    # RFC 9637 IPv6 documentation space. is_global only knows it on CPython 3.12.7+ and
    # 3.13.1+, so it is listed explicitly and this case pins the behaviour.
    "reserved-host-rfc9637-documentation-ipv6": reserved_authority("[3fff::1]"),
    "reserved-host-cgnat": reserved_authority("100.64.0.1"),
    "reserved-host-unspecified": reserved_authority("0.0.0.0"),
    "removed-enum-value-independently-reproducible": removed_enum_value,
    "empty-reproduction-string": empty_reproduction,
    "verification-without-attribution": verification_without_attribution,
    "verification-without-method": verification_without_method,
    "verification-with-impossible-date": verification_with_impossible_date,
    "disputed-without-url": disputed_without_url,
    "disputed-with-non-https-url": disputed_with_non_https_url,
    "disputed-with-blank-note": disputed_with_blank_note,
}


def set_all_dates(obj, value):
    """Set every verified_on in a row. The dates are nested per axis and per implementation,
    so a top-level loop misses most of them, which is how a probe can look like a pass."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "verified_on":
                obj[k] = value
            else:
                set_all_dates(v, value)
    elif isinstance(obj, list):
        for i in obj:
            set_all_dates(i, value)

def run_gate(d, manifest="keep"):
    """Run the gate over directory `d`.

    manifest=None temporarily hides top10.json so the fail-closed behaviour can be tested.
    validate.py resolves the manifest relative to ITS OWN directory, not to the row
    directory, so there is no way to test its absence without moving the real file.
    """
    man = ROOT / "top10.json"
    hidden = ROOT / "top10.json.testhidden"
    moved = False
    try:
        if manifest is None and man.exists():
            man.rename(hidden)
            moved = True
        r = subprocess.run([sys.executable, str(ROOT / "validate.py"), str(d)],
                           capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr
    finally:
        if moved:
            hidden.rename(man)


def mutation_report():
    """Measure whether this suite is vacuous, instead of asserting that it is not.

    An earlier version printed "sabotaging validate.py drops this to 3/28" as a hardcoded
    string on every green run. Nothing computed it. In a suite whose whole argument is that
    an asserted number is not evidence, that was the one number defending the suite itself.

    Each mutant disables one layer of the gate in a throwaway copy of the whole directory
    and re-runs this file against it. A layer that kills few cases is a layer the suite
    barely exercises, which is more useful than a single headline number.
    """
    import shutil, tempfile
    mutants = {
        "semantic layer (check_entry returns no findings)":
            (r"(def check_entry\(entry, today, top10\):\n)", r"\1    return [], []  # MUTANT\n"),
        "schema layer (validator yields no errors)":
            (r"schema_errs = sorted\(validator\.iter_errors\(entry\)[^\n]*",
             "schema_errs = []  # MUTANT"),
        "exit code (always reports success)":
            (r"\n    return 1 if failed else 0", "\n    return 0  # MUTANT"),
    }
    src = (ROOT / "validate.py").read_text()
    base = _suite_score(ROOT)
    print(f"\nMutation report. Baseline: {base[0]} of {base[1]} behaviours correct "
          + "(" + " ".join(f"{k}={g}/{t}" for k, (t, g) in sorted(base[2].items())) + ").")
    for label, (pat, repl) in mutants.items():
        mutated, n = re.subn(pat, repl, src, count=1)
        if not n or mutated == src:
            print(f"  {label:48s}  SKIPPED: pattern no longer matches, mutant is stale")
            continue
        with tempfile.TemporaryDirectory() as td:
            shadow = pathlib.Path(td) / "qsp46"
            shutil.copytree(ROOT, shadow, ignore=shutil.ignore_patterns("__pycache__"))
            (shadow / "validate.py").write_text(mutated)
            ok, tot, pops = _suite_score(shadow)
            detail = " ".join(
                f"{k} {base[2].get(k, (0, 0))[1] - g} of {t} killed"
                for k, (t, g) in sorted(pops.items()))
            print(f"  {label:48s}  {ok:2d} of {tot} still correct "
                  f"-> {base[0] - ok} killed  ({detail})")
    print("\nA mutant that changes nothing would leave the score untouched, which is what "
          "\n'vacuous' would look like. Read the kill counts, not a single number -- and read "
          "\nthem per population: forcing the exit code to success cannot kill a case that "
          "\nexpects acceptance, so only the `reject` column means anything for that mutant.")
    return 0


def _suite_score(root):
    """Run this file against `root`; return (correct, total, {population: (total, correct)})."""
    r = subprocess.run([sys.executable, str(pathlib.Path(root) / "tests" / "test_gate.py")],
                       capture_output=True, text=True)
    out = r.stdout + r.stderr
    m = re.search(r"(\d+) of (\d+) gate behaviours correct", out)
    pops = {}
    b = re.search(r"^breakdown: (.*)$", out, re.M)
    if b:
        for part in b.group(1).split():
            k, _, frac = part.partition("=")
            good, _, tot = frac.partition("/")
            pops[k] = (int(tot), int(good))
    return (int(m.group(1)), int(m.group(2)), pops) if m else (0, 0, pops)


def main():
    results = []

    # --- each MUST_FAIL case, alone in its own directory ---
    for name, fn in MUST_FAIL.items():
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            e = mutate(fn)
            (d / (e.get("slug", "x") + ".json")).write_text(json.dumps(e))
            rc, out = run_gate(d)
            results.append((name, "reject", rc != 0, out))

    # --- the real row must still pass ---
    rc, out = run_gate(ROOT / "protocols")
    results.append(("real-tls-row", "accept", rc == 0, out))

    # --- cross-file: two rows, same slug ---
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        (d / "tls-1-3-key-establishment.json").write_text(json.dumps(GOOD))
        dup = copy.deepcopy(GOOD)
        dup["protocol"] = "TLS1.3"
        (d / "other.json").write_text(json.dumps(dup))
        rc, out = run_gate(d)
        results.append(("duplicate-slug-across-files", "reject", rc != 0, out))

    # --- cross-file: same protocol and mechanism class twice ---
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        (d / "tls-1-3-key-establishment.json").write_text(json.dumps(GOOD))
        twin = copy.deepcopy(GOOD)
        twin["slug"] = "tls-13-ke"
        (d / "tls-13-ke.json").write_text(json.dumps(twin))
        rc, out = run_gate(d)
        results.append(("duplicate-protocol-mechanism", "reject", rc != 0, out))

    # --- a malformed file must not hide a later one ---
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        bad = mutate(impossible_date)
        bad["slug"] = "aaa-bad"
        (d / "aaa-bad.json").write_text(json.dumps(bad))
        stale = mutate(ancient_evidence)
        stale["slug"] = "zzz-stale"
        (d / "zzz-stale.json").write_text(json.dumps(stale))
        rc, out = run_gate(d)
        both = "aaa-bad.json" in out and "zzz-stale.json" in out
        results.append(("malformed-file-does-not-hide-later-rows", "reject both", rc != 0 and both, out))

    # --- case and recursion: these were invisible to version 1 ---
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        (d / "tls-1-3-key-establishment.json").write_text(json.dumps(GOOD))
        (d / "nested").mkdir()
        (d / "nested" / "sneaky.JSON").write_text(json.dumps(mutate(ancient_evidence)))
        rc, out = run_gate(d)
        results.append(("uppercase-and-nested-are-seen", "reject", rc != 0 and "sneaky" in out.lower(), out))

    # --- a stray non-json file under protocols/ is reported ---
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        (d / "tls-1-3-key-establishment.json").write_text(json.dumps(GOOD))
        (d / "notes.txt").write_text("x")
        rc, out = run_gate(d)
        results.append(("stray-file-reported", "reject", rc != 0, out))

    # --- needs-owner: stale WITHIN the grace window is reported, not fatal ---
    # Dated just past the 90d implementation TTL but inside the 30d grace, so the row is
    # visible as unowned without blocking the build.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = copy.deepcopy(GOOD)
        e["row_state"] = "needs-owner"
        # ONLY the implementation axis: aging every date also pushes the standardisation
        # evidence behind RFC 10024's publication date, which trips the separate
        # published-after-evidence rule that needs-owner deliberately does NOT suppress.
        set_all_dates(e["axes"]["implementation"],
                      (dt.date.today() - dt.timedelta(days=100)).isoformat())
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        results.append(("needs-owner-within-grace-warns-not-fails", "accept with warning",
                        rc == 0 and "warn" in out, out))

    # --- needs-owner is BOUNDED: it cannot be a permanent opt-out ---
    # This is the v1 defect in different clothing. In v1 the cheapest way to pass was to bump
    # one authored date; with an unbounded needs-owner the cheapest way was to type one word,
    # and the gate then ignored staleness forever. Past TTL + grace it must fail.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = copy.deepcopy(GOOD)
        e["row_state"] = "needs-owner"
        set_all_dates(e, (dt.date.today() - dt.timedelta(days=400)).isoformat())
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        results.append(("needs-owner-cannot-suppress-forever", "reject", rc != 0, out))

    # --- the escape hatch works when it is used honestly ---
    # `unknown` plus a reason must VALIDATE, or the field still forces a guess and the
    # addition is cosmetic. The basis field itself was impossible before this change:
    # additionalProperties:false rejected it with four schema errors, so an author could
    # neither say "not established" nor say why.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = copy.deepcopy(GOOD)
        ev = e["axes"]["standardisation"]["evidence"]
        ev["independence"] = "unknown"
        ev["independence_basis"] = ("Authors' affiliations are not stated in the document and "
                                    "could not be resolved from the IETF datatracker entry.")
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        results.append(("unknown-independence-with-basis-accepted", "accept",
                        rc == 0 and "unknown:1" in out, out))

    # --- independence must be CONSEQUENTIAL, not decorative ---
    # The defect this closes: the field was required on every evidence object and no rule in
    # the gate read it, so flipping every block from the strongest value to the weakest left
    # the verdict byte-identical. Measured 2026-10-31. This case fails if that is ever true
    # again, which is the only way to keep a required field from becoming an unchecked claim.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        baseline = copy.deepcopy(GOOD)
        (d / (baseline["slug"] + ".json")).write_text(json.dumps(baseline))
        rc_a, out_a = run_gate(d)
        flipped = copy.deepcopy(GOOD)
        for ev in _all_evidence(flipped):
            ev["independence"] = "third-party"
        (d / (flipped["slug"] + ".json")).write_text(json.dumps(flipped))
        rc_b, out_b = run_gate(d)
        # The output must DIFFER, because the value is printed beside every axis status and
        # in the row census. It must not differ in WARNINGS: see
        # `no-label-pattern-buys-a-cleaner-run` below, which is the other half of this.
        differs = (out_a != out_b
                   and "/first-party" in out_a and "/third-party" in out_b
                   and out_a.count("warn:") == out_b.count("warn:"))
        results.append(("independence-is-read-not-decorative", "accept both, differ",
                        rc_a == 0 and rc_b == 0 and differs, out_a + "\n--- flipped ---\n" + out_b))

    # --- a row resting entirely on evidence that establishes nothing stays VISIBLE ---
    # `unknown` is the honest value and it must not be quiet. The first round graded it as
    # weak and warned, which this case asserted via the warning text; the grading is gone, so
    # the assertion moved to the printed provenance, where it is not gameable. The blind spot
    # that motivated it is still worth recording: with only a first-party arm asserted, a
    # one-word mutant of the weak-value list left the whole suite green.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = copy.deepcopy(GOOD)
        for ev in _all_evidence(e):
            ev["independence"] = "unknown"
            ev["independence_basis"] = "Affiliation not stated in the source."
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        # Count derived from the row, not hardcoded. Adding two exposures to the exemplar
        # broke this case and `reproduction-is-optional-and-earns-nothing` at the same time,
        # which is the positional brittleness that `doc_by_id` fixed one field over.
        n = len(list(_all_evidence(e)))
        results.append(("unknown-only-evidence-is-reported", "accept, provenance shown",
                        rc == 0 and f"unknown:{n}" in out and "/unknown" in out, out))

    # --- NO label pattern buys a cleaner run. This is @leprecha1's third point, measured. ---
    # Two earlier attempts both failed this. 40f737f warned when an axis rested only on weak
    # evidence, so the honest exemplar as shipped earned one warning and an all-`third-party`
    # fabrication of the same row earned none. A uniformity warning fixed that case and immediately
    # rewarded a fabricated MIX. The invariant below is what rules the whole family out:
    # relabelling every block, in any direction, must not change how many warnings a row
    # earns. Only absences warn, and relabelling cannot fill an absence.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        honest = copy.deepcopy(GOOD)
        (d / (honest["slug"] + ".json")).write_text(json.dumps(honest))
        rc_h, out_h = run_gate(d)
        counts = {}
        for label in ("first-party", "derivative", "third-party", "unknown"):
            e = copy.deepcopy(GOOD)
            for ev in _all_evidence(e):
                ev["independence"] = label
                ev["independence_basis"] = "x"
            (d / (e["slug"] + ".json")).write_text(json.dumps(e))
            rc, out = run_gate(d)
            counts[label] = (rc, out.count("warn:"))
        same = {v for v in counts.values()} == {(rc_h, out_h.count("warn:"))}
        results.append(("no-label-pattern-buys-a-cleaner-run", "same warnings for every label",
                        same, f"honest={(rc_h, out_h.count('warn:'))} relabelled={counts}"))

    # --- and the fabrication that the gate genuinely CANNOT catch, asserted as passing ---
    # Stated as a test so the README's gap 3 cannot quietly become a claim that it is closed.
    # Every block third-party with a one-word basis, every excerpt invented and marked
    # verbatim, dated today, under a host the gate cannot rule out: this passes, and the
    # only thing that would stop it is fetching `source` and checking `excerpt` against it.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = copy.deepcopy(GOOD)
        for ev in _all_evidence(e):
            ev["independence"] = "third-party"
            ev["independence_basis"] = "An independent laboratory."
            ev["source"] = FIXTURE_HOST + "/report"
            ev["excerpt"] = "Fully interoperable and deployed by default everywhere."
            ev["verbatim"] = "yes"
            ev["verified_on"] = dt.date.today().isoformat()
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        results.append(("plausible-host-fabrication-still-passes", "accept (gap 3, stated)",
                        rc == 0, out))

    # --- an exposure with no evidence is reported ---
    # Version 2 could not express one at all: known_exposures items set
    # additionalProperties:false with no evidence property, so all five exposures on the
    # exemplar were unevidenced by contract, in the axis the proposal calls most important.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = copy.deepcopy(GOOD)
        for exp in e["axes"]["failure_mode"]["known_exposures"]:
            exp.pop("evidence", None)
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        n = out.count("carries no evidence")
        results.append(("every-unevidenced-exposure-is-reported", "accept, one warn each",
                        rc == 0 and n == len(e["axes"]["failure_mode"]["known_exposures"]),
                        f"warned {n} times\n" + out))

    # --- an internationalised domain in punycode is still accepted ---
    # The IDNA normalisation runs ToASCII over every host, so the negative control matters:
    # an over-eager version would reject legitimate punycode citations.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = copy.deepcopy(GOOD)
        for ev in _all_evidence(e):
            ev["source"] = "https://xn--e1afmkfd.xn--p1ai/report"
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        results.append(("punycode-idn-host-is-accepted", "accept", rc == 0, out))

    # --- a globally reachable host, including a bare IP, is still accepted ---
    # The IP rule rejects "not globally reachable", so the negative control matters: an
    # over-broad version of it would reject every real citation that uses an address.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = copy.deepcopy(GOOD)
        for ev in _all_evidence(e):
            ev["source"] = "https://93.184.216.34/report"
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        results.append(("globally-reachable-ip-literal-is-accepted", "accept", rc == 0, out))

    # --- `derivative` is accepted, and exists because the axis was not exhaustive ---
    # A blog restating a vendor's release notes is not the subject, so it is not first-party,
    # and it took the subject's word for it, so it is not third-party. Under the previous
    # enum it had no correct value, which is how a required field gets a wrong answer.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = copy.deepcopy(GOOD)
        ev = e["axes"]["standardisation"]["evidence"]
        ev["independence"] = "derivative"
        ev["independence_basis"] = ("Trade-press article restating the IETF announcement "
                                    "rather than independently establishing publication.")
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        results.append(("derivative-is-accepted-with-a-basis", "accept",
                        rc == 0 and "derivative:1" in out, out))

    # --- reproduction is optional, and earns nothing ---
    # It replaced the enum value `independently-reproducible`. Nothing here re-runs it, so a
    # row must neither need it nor benefit from it; it is printed as a count and no more.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        bare = copy.deepcopy(GOOD)
        for ev in _all_evidence(bare):
            ev.pop("reproduction", None)
        (d / (bare["slug"] + ".json")).write_text(json.dumps(bare))
        rc_a, out_a = run_gate(d)
        full = copy.deepcopy(GOOD)
        for ev in _all_evidence(full):
            ev["reproduction"] = "Re-run the published harness at the pinned tag."
        (d / (full["slug"] + ".json")).write_text(json.dumps(full))
        rc_b, out_b = run_gate(d)
        n = len(list(_all_evidence(full)))
        results.append(("reproduction-is-optional-and-earns-nothing", "accept both, same warns",
                        rc_a == 0 and rc_b == 0
                        and out_a.count("warn:") == out_b.count("warn:")
                        and "repro=0/" in out_a and f"repro={n}/{n}" in out_b,
                        out_a + out_b))

    # --- a FAILED pair cannot speak for a claim that the pair interoperates ---
    # This gate already filters the multi-vendor vendor count on `result == "interoperates"`.
    # The independence check did not, so a disinterested report that a pair FAILED cleared
    # the warning on a `pairwise` status still earned entirely by first-party evidence.
    # Found in review 2026-10-31; the same defect one rule over.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = copy.deepcopy(GOOD)
        today = dt.date.today().isoformat()
        e["axes"]["interoperability"] = {"status": "pairwise", "tested_pairs": [
            {"a": "OpenSSL", "b": "Go crypto/tls", "result": "interoperates",
             "evidence": fixture_evidence(source_kind="release-notes",
                                         independence="first-party")},
            {"a": "OpenSSL", "b": "Go crypto/tls", "result": "fails",
             "evidence": fixture_evidence()}]}
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        # The printed provenance for a `pairwise` status must come from the pair that
        # INTEROPERATES, not from a disinterested report that a pair FAILED. This gate
        # already filters the multi-vendor vendor count that way; the provenance did not,
        # so a failure was being credited to the claim it refutes.
        results.append(("failed-pair-does-not-supply-pairwise-provenance",
                        "accept, provenance from the working pair",
                        rc == 0 and "intero=pairwise/first-party" in out, out))

    # --- nor can an implementation that is not the one earning the status ---
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = copy.deepcopy(GOOD)
        e["axes"]["implementation"]["implementations"].append({
            "name": "IrrelevantStack", "version": "0.1", "default_enabled": "no",
            "algorithms": ["X25519MLKEM768"],
            "evidence": fixture_evidence()})
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        results.append(("non-default-implementation-does-not-supply-provenance",
                        "accept, provenance from the default-on entries",
                        rc == 0 and "implem=default-on/first-party" in out, out))

    # --- `verification` is a separate attestation and it EARNS A ROW NOTHING ---
    # @leprecha1's point 3 on issue #46: independent verification must be separately
    # attributable, not inferred from a `third-party` label. The load-bearing property is
    # that it cannot improve a row, for the same reason the two grading rules were removed:
    # nothing offline can check an attestation, so anything keyed to its presence would
    # reward typing it. Adding it to every block must not change a single warning.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        bare = copy.deepcopy(GOOD)
        # Stripped EXPLICITLY. The exemplar now carries one verification block to demonstrate
        # the self-attestation case, so assuming the baseline has none broke this case the
        # moment the row gained one. Derive the state you are comparing against.
        for ev in _all_evidence(bare):
            ev.pop("verification", None)
        (d / (bare["slug"] + ".json")).write_text(json.dumps(bare))
        rc_a, out_a = run_gate(d)
        full = copy.deepcopy(GOOD)
        for ev in _all_evidence(full):
            ev["verification"] = {
                "verified_by": "an unrelated reviewer",
                "verified_on": dt.date.today().isoformat(),
                "method": "re-fetched the source and re-read the cited section",
                "source": "https://github.com/OWASP/quantum-security-project/issues/46",
            }
        (d / (full["slug"] + ".json")).write_text(json.dumps(full))
        rc_b, out_b = run_gate(d)
        n = len(list(_all_evidence(full)))
        results.append(("verification-earns-a-row-nothing", "accept both, same warns",
                        rc_a == 0 and rc_b == 0
                        and out_a.count("warn:") == out_b.count("warn:")
                        and f"verified=0/{n}" in out_a and f"verified={n}/{n}" in out_b,
                        out_a + out_b))

    # --- a self-attestation is allowed and is VISIBLE as one ---
    # This is the case that could not be typed before: reading TLS_DEFAULT_GROUP_LIST at a
    # pinned tag is reproducible and is not independently verified. The field does not
    # forbid the maintainer's own name; it makes whose name it carries inspectable, which is
    # the distinction @leprecha1 drew.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = copy.deepcopy(GOOD)
        ev = e["axes"]["implementation"]["implementations"][0]["evidence"]
        ev["verification"] = {
            "verified_by": e["maintainer"],
            "verified_on": dt.date.today().isoformat(),
            "method": "read TLS_DEFAULT_GROUP_LIST at tag openssl-3.5.0",
        }
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        results.append(("a-self-attestation-is-accepted-and-named", "accept",
                        rc == 0 and "verified=1/" in out, out))

    # --- a dispute is PRINTED, and does not fail the row ---
    # Gap 5's mechanism. The gate does not adjudicate: a disputed cell may be correct, so a
    # dispute cannot be a failure. But it must be impossible to miss, because the entire
    # point is that a reader who disagrees gets somewhere in the DATA to say so.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = copy.deepcopy(GOOD)
        ev = e["axes"]["standardisation"]["evidence"]
        ev["disputed"] = {
            "url": "https://github.com/OWASP/quantum-security-project/issues/46",
            "note": "RFC 10024 is the document itself, not third-party evidence about it",
            "raised_on": dt.date.today().isoformat(),
        }
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        results.append(("a-dispute-is-printed-and-does-not-fail-the-row",
                        "accept, dispute shown",
                        rc == 0 and "DISPUTED:" in out and "issues/46" in out, out))

    # --- a dispute cannot be used to improve a row either ---
    # Symmetry check. Neither new field may move a verdict in EITHER direction, or it
    # becomes a lever. A disputed row earns one more line and the same exit code.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        base = copy.deepcopy(GOOD)
        (d / (base["slug"] + ".json")).write_text(json.dumps(base))
        rc_a, out_a = run_gate(d)
        disp = copy.deepcopy(GOOD)
        for ev in _all_evidence(disp):
            ev["disputed"] = {"url": "https://github.com/OWASP/quantum-security-project/issues/46",
                              "note": "every cell on this row is disputed"}
        (d / (disp["slug"] + ".json")).write_text(json.dumps(disp))
        rc_b, out_b = run_gate(d)
        n = len(list(_all_evidence(disp)))
        results.append(("a-dispute-changes-the-exit-code-for-nobody", "accept both",
                        rc_a == 0 and rc_b == 0
                        and out_b.count("DISPUTED:") == n, out_a + out_b))

    # --- a FAILING row prints its independence counts too ---
    # The print was in the pass branch only, withholding the mix from the one reader who
    # needs it most: whoever is fixing the row. Raised in review 2026-10-31.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = mutate(default_on_unsupported)
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        results.append(("failing-rows-print-independence-counts", "reject, with counts",
                        rc != 0 and "FAIL" in out and "indep=" in out, out))

    # --- a FAILING row also prints the per-axis provenance ---
    # The README claims the label is printed beside the status it supports "on every row, pass
    # or fail". It was built inside the pass branch only, so a failing row printed the census
    # and no provenance at all: the branch where a reader needs it most, and the same defect as
    # the census one commit earlier, in the line added to fix that one. Reproduced 2026-10-31.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        e = mutate(bogus_related)
        (d / (e["slug"] + ".json")).write_text(json.dumps(e))
        rc, out = run_gate(d)
        fail_line = next((l for l in out.splitlines() if l.startswith("FAIL")), "")
        results.append(("failing-rows-print-axis-provenance", "reject, with provenance",
                        rc != 0 and "implem=default-on/first-party" in fail_line
                        and "oldest_evidence=" in fail_line, out))

    # --- the manifest must fail CLOSED, not open ---
    # Deleting top10.json previously made every related_owasp_entries value pass: a row citing
    # QS99 validated with exit 0, in a gate advertised as failing closed.
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        (d / "tls-1-3-key-establishment.json").write_text(json.dumps(GOOD))
        rc, out = run_gate(d, manifest=None)
        results.append(("missing-manifest-refuses-to-run", "reject", rc != 0, out))

    # --- the gate fails closed without jsonschema ---
    with tempfile.TemporaryDirectory() as td:
        shadow = pathlib.Path(td)
        (shadow / "jsonschema.py").write_text('raise ImportError("shadowed")\n')
        import os
        env = dict(os.environ, PYTHONPATH=str(shadow))
        r = subprocess.run([sys.executable, str(ROOT / "validate.py"), str(ROOT / "protocols")],
                           capture_output=True, text=True, env=env)
        ok = r.returncode == 2 and "jsonschema is required" in (r.stdout + r.stderr)
        results.append(("fails-closed-without-jsonschema", "refuse to run", ok, r.stdout + r.stderr))

    width = max(len(n) for n, _, _, _ in results)
    ewidth = max(len(e) for _, e, _, _ in results)
    bad = 0
    print("  Each line: did the gate do the right thing with this input?")
    print()
    for name, expect, ok, out in results:
        mark = "ok     " if ok else "BROKEN "
        print(f"  {mark}{name:<{width}}  gate should {expect:<{ewidth}}  {'and did' if ok else 'BUT DID NOT'}")
        if not ok:
            bad += 1
            for line in out.strip().splitlines()[:6]:
                print(f"          {line}")
    print()
    print(f"{len(results) - bad} of {len(results)} gate behaviours correct"
          + ("" if bad else "  (run with --mutate to measure whether this suite is vacuous)"))
    # Machine-readable, for the mutation report to split by population. A case expecting
    # REJECTION can die when the exit code is forced to success; a case expecting acceptance
    # cannot, because the mutant agrees with it. Aggregating the two made that mutant's
    # number drift upward every time an acceptance case was added, which looked like the
    # suite weakening when it was the metric mixing populations.
    pops = {}
    for name, expect, ok, _ in results:
        key = "reject" if (expect.startswith("reject") or expect == "refuse to run") else "accept"
        tot, good = pops.get(key, (0, 0))
        pops[key] = (tot + 1, good + (1 if ok else 0))
    print("breakdown: " + " ".join(f"{k}={g}/{t}" for k, (t, g) in sorted(pops.items())))
    return 1 if bad else 0


if __name__ == "__main__":
    if "--mutate" in sys.argv:
        sys.exit(mutation_report())
    sys.exit(main())
