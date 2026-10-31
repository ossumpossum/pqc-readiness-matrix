# PQC Protocol Readiness Matrix: data contract

Strawman for [#46](https://github.com/OWASP/quantum-security-project/issues/46). One file per
protocol-and-mechanism-class pair under `protocols/`, validated in CI.

```
pqc-readiness.schema.json   JSON Schema 2020-12, the contract
protocols/*.json            one row each, filename stem == slug
top10.json                  manifest that related_owasp_entries is checked against
validate.py                 the gate: schema + semantics + cross-file
tests/test_gate.py          36 behaviours the gate must have
requirements.txt            pinned, hash-pinned for CI
```

Run locally: `pip install -r requirements.txt && python3 tests/test_gate.py && python3 validate.py protocols`

## The two decisions worth arguing about

**1. `last_verified` is not a field.** It was in version 1, and that was the design's central flaw:
a contributor wrote the date by hand and the only staleness check read that field, so the cheapest way
to pass the gate was to bump one date and re-verify nothing. The gate rewarded exactly the behaviour it
existed to prevent.

Here, each axis's effective verification date is **derived** as the oldest `verified_on` among the
evidence supporting it. A renderer can still show a "last verified" column; it is computed rather than
typed. TTLs are per axis, because one global number is wrong in both directions:

| Axis | TTL | Why |
|---|---|---|
| standardisation | 365d | An RFC number does not rot in six months |
| implementation | 90d | A `default-on` claim can rot faster than this, so treat 90d as an enforceable review cadence rather than a guarantee |
| interoperability | 180d | A plugfest result ages with the stacks, not with the spec |
| failure_mode | 180d | Tracks deployment behaviour, which moves with implementations |

Each axis has **one** floor status that asserts nothing and is therefore exempt: `none` for
standardisation and implementation, `not_assessed` for interoperability and failure_mode. Note that
`interoperability: none` is a positive claim that nothing interoperates, so it still needs evidence.

One other exemption, stated because it is the obvious way to game this: `row_state: needs-owner`
downgrades a TTL breach to a warning, so an orphaned row stays visible instead of blocking the build.
It is **bounded at TTL plus 30 days**, so it cannot become a one-word permanent opt-out. An earlier cut
had it unbounded, which was the authored-date defect in different clothing.

What this does not buy: a contributor still types `verified_on`, so a false date remains possible. What
it does buy is that decay is non-silent and each claim is refutable on its own, because a date now sits
beside the URL it claims to have checked.

**2. One row per mechanism class.** `mechanism_class` is `key-establishment` or `authentication`,
and a protocol gets one row for each. Without this, TLS reads `published` and `default-on`, which a
defender asking "is TLS quantum-ready?" reads as yes. It is ready for key establishment; for
authentication the standards work is still moving and the binding constraint is public Web PKI
issuance. A single row cannot say both. Version 1 had no way to express the distinction, which made
its own exemplar the most misleading thing in it.

Two classes is the smallest split that fixes the TLS case, not a claim to be the universal taxonomy:
SSH wants KEX plus host auth plus user auth, DNSSEC has no key establishment at all, and a Noise-style
static key does both jobs in one primitive. Whoever owns those rows should name their own classes.

## Evidence provenance: what each `independence` value means

Added after review on [#46](https://github.com/OWASP/quantum-security-project/issues/46), where
@leprecha1 asked for reproducible criteria per value, an explicit way to say "not established", and
an assurance that mandatory classification does not become a substitute for verification. All three
were right, and the first two were simply missing: the field carried a one-line rationale and no test.

**Independence is a property of the evidence-to-claim pair, not of the document.** The same RFC is
third-party evidence that a mechanism is standardised and first-party evidence that its own authors'
product ships it. That is why the field sits on each evidence object rather than on a registry of
sources, and why the same URL can legitimately carry different values on two different rows.

| Value | The test | Typical case | Basis required |
|---|---|---|---|
| `first-party` | The evidence author and the subject of the claim share an interest | A vendor's release notes about that vendor's implementation; a specification written by the implementers; vendor telemetry | no |
| `third-party` | The author is not the subject and did not take the subject's word for it | An independent test report; a CVE analysis; a paper measuring someone else's code | no |
| `independently-reproducible` | A reader holding the named artifacts can re-run it and get the same answer | A published test harness with pinned versions; a plugfest procedure anyone can repeat | **yes**, naming what to re-run |
| `unknown` | Cannot be established from the source | Authorship or affiliation not stated and not resolvable | **yes**, saying why |

`independence_basis` is required for the last two and optional for the first two. The asymmetry is
deliberate: `unknown` needs a reason so it cannot become a dump, and `independently-reproducible` is
the strongest value in the enum while previously asserting reproducibility without naming anything to
reproduce. `first-party` and `third-party` are cheap for a reviewer to check against the source URL.

**Three residuals, stated rather than implied.**

1. **Nothing stops `third-party` being typed over a vendor URL**, and that is now the cheapest false
   value in the enum because it needs no basis. The gate cannot settle it. What it can do is show the
   mix, which it does: every passing row prints its `indep=` counts, so a vendor host sitting under a
   `third-party` label is visible to a reader. That is contestability by display rather than by
   validation, and it is the honest limit.
2. **`unknown` is not an exemption.** It describes the evidence, not a floor status, so it does not
   relax a TTL and does not excuse a status from needing evidence.
3. **Provenance is not validity.** This schema records where a claim came from, which is cheap, and
   cannot assess whether the claim is true, which is not. Classification must not be read as a trust
   score, which is why the gate prints counts and never a composite number. The step that would turn
   provenance into verification is fetching `source` and confirming `excerpt` appears there; that is
   gap 3 and it is not done.

## What the gate enforces beyond types

- A status must be earned by its own contents: `published` needs a document, `pairwise` needs a pair
  that actually interoperates, `multi-vendor` needs three distinct stacks **appearing in pairs that
  interoperate**, `default-on` needs an implementation with `default_enabled: yes`, `reverted` needs a
  `withdrawn_in_version`.
- A standardisation status of `approved` or later requires at least one cited document carrying a real
  `published` date. Without that, the staleness rule below has nothing to read: `published` is optional
  on five of the ten document statuses, so a row could claim the standards work was done while citing
  only undated documents.
- Dates are parsed, not pattern-matched. `2026-02-30` satisfies the schema and is rejected here.
- A document published after the row's own evidence means the row is stale, not that the date is
  impossible.
- `superseded_by` on a document forces the axis status to `superseded`, `deprecated` or `withdrawn`.
- Cross-file: slug uniqueness, slug equals filename stem, and one row per protocol-and-class pair, so
  two contradictory rows **that name the protocol the same way** cannot both pass. The protocol name is
  normalised to alphanumerics first, so `TLS1.3` and `TLS 1.3` collide as intended; see gap 9 for what
  that still does not catch.
- `independence` is **read**, which it previously was not. It was required on every evidence object
  and no rule consulted it, so flipping every block on a row from `independently-reproducible` to
  `first-party` left the verdict byte-identical: a required field that nothing checked. An axis above
  its floor whose supporting evidence is entirely `first-party` or `unknown` is now **reported**, and
  every passing row prints its independence counts.
  This reports and does not fail, and the exemplar is the reason: its implementation axis is
  `default-on` on two first-party sources, because a vendor's own release notes are the best evidence
  that exists for that vendor's default. A gate that failed such a row would not produce better
  evidence, it would produce rows relabelled to get green. Making it fail is a one-line change if the
  project decides a status above some threshold must carry a disinterested source, but that is a
  policy call for the project rather than for this gate.
- Discovery is recursive and case-insensitive, and a stray non-JSON file under `protocols/` is a
  failure, because a renderer may still read it.
- The gate **fails closed** in both directions that matter. Without `jsonschema` it exits 2 rather than
  printing success, and a missing or empty `top10.json` is refused rather than treated as an empty
  allowlist, which previously let a row cite a non-existent entry and validate.

`tests/test_gate.py` covers 36 behaviours, most of which exist because an earlier version of this gate
accepted a row it should have rejected. `tests/test_gate.py --mutate` disables one layer of the gate at
a time in a throwaway copy and re-runs everything, so the suite's dependence on each layer is
measurable rather than asserted. Measured on 2026-10-31: disabling the semantic checks leaves 23 of 36
correct, disabling the schema layer 25 of 36, and forcing the exit code to success 6 of 36.

## Known gaps, stated rather than discovered later

These are limits of what is here, not a to-do list for the project.

1. **No renderer, and this is the most important gap.** Thirty JSON files are unreadable to a defender.
   Without a generator someone will hand-maintain a Markdown table and the staleness problem reappears
   downstream in an artifact nothing validates. It is a small generator over `protocols/*.json` and it
   is next, but it is not in this drop.
2. **Draft currency is not checked.** The schema requires a revision suffix on an Internet-Draft id,
   which catches an unversioned reference and **does not** catch a renamed or replaced one. A row citing
   `draft-kwiatkowski-tls-ecdhe-mlkem-00` validates today, and that is the exact stale citation this
   design is reacting to. Closing it needs a CI step resolving each id against the IETF Datatracker and
   asserting the revision is current and the state is not `replaced`. The exemplar's citations were
   checked by hand on 2026-10-30; doing it by hand is the gap.
3. **No link checking and no content verification.** `source` must be `https://`, and nothing fetches
   it, snapshots it, or confirms that `excerpt` appears there. `verbatim: yes` is an author's assertion.
   While rebuilding this, two of the exemplar's own excerpts were found truncated immediately before a
   clause that qualified the claim, which is why that field cannot be trusted without a check.
4. **The review burden is real.** One row per mechanism class means up to 60 rows for 30 protocols,
   600 or more evidence blocks, and with these TTLs roughly 540 axis re-verifications a year. That is
   not sustainable by one person. Six to eight rows is the sane starting point: TLS twice, SSH twice,
   IKEv2, DNSSEC.
5. **No way to contest a cell.** One maintainer, one evidence block per claim. There is no `disputed`
   flag, no second attestation, and no way for a claim to carry two independent sources, which is the
   property that matters most when a source is first-party. Partly narrowed on 2026-10-31: a
   first-party-only axis is now reported and every row prints its independence counts, so the
   condition is at least **visible**. Visible is not contestable. A reader who disagrees with a cell
   still has nowhere in the data to say so, and that remains open.
6. **A PR is checked by its own copy of the gate.** The workflow checks out the PR head, so a PR that
   edits both a row and `validate.py` grades itself, and a green check on such a PR means nothing. This
   is inherent to `pull_request` CI rather than specific to this design; the mitigation is human review
   of changes to the gate itself before trusting its verdict.
7. **A weekly cron is a backstop, not a mechanism.** GitHub documents that "in a public repository,
   scheduled workflows are automatically disabled when no repository activity has occurred in 60 days".
   The docs do not define "repository activity", and the clock runs on activity rather than on the
   workflow's age, so the practical limitation is that on a quiet repository the staleness check can
   silently stop, which is exactly when rows are going stale. Re-enabling needs a UI or API action, or a
   commit that changes the cron. PR-time validation is the real gate.
8. **Bus factor: one.** The `maintainer_backup` field in the exemplar is empty, and it exists so that
   emptiness is visible. The implementation axis has a 90-day TTL and the exemplar's implementation
   evidence is dated 2026-10-14, so that row's gate starts failing on **2027-01-12** if nobody
   refreshes it. That is the design working as intended, and it also means a required check depends on
   one person.
9. **Protocol names are free text.** Normalising to alphanumerics catches `TLS1.3` against `TLS 1.3`;
   it does not catch `TLSv1.3`, so two contradictory rows can still coexist under different spellings.
   The fix is a controlled vocabulary: an enum, or a committed protocol registry. Not here.
10. **The suite asserts rejection, not the reason.** Each of the 32 cases checks that the gate exits
    non-zero, not which rule fired, so an over-broad rule could satisfy several cases for the wrong
    reason. The mutation report is a partial answer; asserting an expected message per case is the real
    one.

## On serialisation

This is JSON because the gate reads JSON today. The schema is serialisation-independent in principle,
but nothing here parses YAML, and if authors wrote YAML every date would need quoting or a loader
change: YAML 1.1 resolves an unquoted `2026-10-30` to `tag:yaml.org,2002:timestamp`, and PyYAML
implements that resolver, so `yaml.safe_load` returns a `datetime.date` and a `type: string` constraint
on the loaded object fails.

The YAML 1.1 `no`-parses-as-boolean hazard is **not** the reason. The YAML 1.2 core schema resolves
only `true|True|TRUE|false|False|FALSE` as booleans and sends everything else unmatched to
`tag:yaml.org,2002:str`, so bare `no` is a string under 1.2. PyYAML, however, describes itself as a
complete YAML 1.1 parser: it validates a `%YAML 1.2` directive and records it, but never consults it
when resolving plain scalars, so `yaml.safe_load("a: no")` still returns `False`. YAML 1.2 also drops
the timestamp type entirely, yet `ruamel.yaml` keeps the timestamp resolver even in 1.2 mode. So this
is parser behaviour to handle rather than spec behaviour to rely on.

If the project would rather author YAML and generate JSON for consumers, the loader is a few lines and
can be added.
