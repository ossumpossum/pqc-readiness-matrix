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


def mutate(fn):
    e = copy.deepcopy(GOOD)
    fn(e)
    return e


def no_documents(e):
    e["axes"]["standardisation"] = {"status": "published", "documents": []}


def blank_implementation(e):
    e["axes"]["implementation"] = {
        "status": "default-on",
        "implementations": [{
            "name": "  ", "version": "1", "default_enabled": "yes", "algorithms": ["x"],
            "evidence": {"source_kind": "release-notes", "independence": "first-party",
                         "source": "https://example.test/x", "verified_on": "2026-10-14"}}]}


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
                          "evidence": {"source_kind": "test-report", "independence": "third-party",
                                       "source": "https://example.test/r", "verified_on": "2026-10-14"}}]}


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
    e["axes"]["standardisation"]["documents"][0]["superseded_by"] = "RFC 99999"


def doc_published_after_evidence(e):
    e["axes"]["standardisation"]["documents"][0]["published"] = "2026-10-20"


def boolean_enum(e):
    e["axes"]["standardisation"]["status"] = False


def wrong_schema_version(e):
    e["schema_version"] = 1


def rfc_without_published(e):
    e["axes"]["standardisation"]["documents"][0].pop("published")


def unversioned_draft(e):
    e["axes"]["standardisation"]["documents"][2]["id"] = "draft-ietf-uta-pqc-app"


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
        "url": "https://example.test/doc",
    }]


def unknown_independence_without_basis(e):
    """Use the honest value without saying why it could not be established.

    `unknown` was added to the enum after @leprecha1 raised, on issue #46, that a mandatory
    classification with no escape hatch forces an author to assert independence they cannot
    establish. The escape hatch must not be cheaper than the three positive values it exists
    to replace, or it becomes the default and the field means nothing again.
    """
    e["axes"]["standardisation"]["evidence"]["independence"] = "unknown"


def provenance_maximal_without_basis(e):
    """The strongest value in the enum on every block, asserted and unexplained.

    Measured on 2026-10-31 against the previous gate: this row passed with exit 0 while every
    source was `https://example.invalid/...`, every excerpt was invented and marked
    `verbatim: yes`, and it reported `oldest_evidence=0d` against the real row's 17d, so the
    fabricated row graded as the fresher of the two. `independently-reproducible` now costs a
    sentence naming what to re-run.

    What this case does NOT prove: adding a plausible basis string makes this row pass again,
    because nothing fetches `source`. That is gap 3, and it is the only thing that would turn
    provenance into verification.
    """
    for ev in _all_evidence(e):
        ev["independence"] = "independently-reproducible"
        ev["source"] = "https://example.invalid/pqc/does-not-exist"
        ev["excerpt"] = "This document confirms the mechanism is fully deployed and interoperable."
        ev["verbatim"] = "yes"


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
    print(f"\nMutation report. Baseline: {base[0]} of {base[1]} behaviours correct.")
    for label, (pat, repl) in mutants.items():
        mutated, n = re.subn(pat, repl, src, count=1)
        if not n or mutated == src:
            print(f"  {label:48s}  SKIPPED: pattern no longer matches, mutant is stale")
            continue
        with tempfile.TemporaryDirectory() as td:
            shadow = pathlib.Path(td) / "qsp46"
            shutil.copytree(ROOT, shadow, ignore=shutil.ignore_patterns("__pycache__"))
            (shadow / "validate.py").write_text(mutated)
            ok, tot = _suite_score(shadow)
            print(f"  {label:48s}  {ok:2d} of {tot} still correct "
                  f"-> {base[0] - ok} case(s) depend on this layer")
    print("\nA mutant that changes nothing would leave the score untouched, which is what "
          "\n'vacuous' would look like. Read the kill counts, not a single number.")
    return 0


def _suite_score(root):
    """Run this file against `root` and return (correct, total) parsed from its own output."""
    r = subprocess.run([sys.executable, str(pathlib.Path(root) / "tests" / "test_gate.py")],
                       capture_output=True, text=True)
    m = re.search(r"(\d+) of (\d+) gate behaviours correct", r.stdout + r.stderr)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


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
            ev["independence"] = "first-party"
        (d / (flipped["slug"] + ".json")).write_text(json.dumps(flipped))
        rc_b, out_b = run_gate(d)
        differs = (out_a != out_b
                   and out_b.count("rests only on") > out_a.count("rests only on"))
        results.append(("independence-is-read-not-decorative", "accept both, differ",
                        rc_a == 0 and rc_b == 0 and differs, out_a + "\n--- flipped ---\n" + out_b))

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
    return 1 if bad else 0


if __name__ == "__main__":
    if "--mutate" in sys.argv:
        sys.exit(mutation_report())
    sys.exit(main())
