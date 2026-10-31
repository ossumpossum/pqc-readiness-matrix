# PQC Protocol Readiness Matrix: data contract

Strawman for [#46](https://github.com/OWASP/quantum-security-project/issues/46). One file per
protocol-and-mechanism-class pair under `protocols/`, validated in CI.

```
pqc-readiness.schema.json   JSON Schema 2020-12, the contract
protocols/*.json            one row each, filename stem == slug
top10.json                  manifest that related_owasp_entries is checked against
validate.py                 the gate: schema + semantics + cross-file
tests/test_gate.py          72 behaviours the gate must have
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
| failure_mode | 180d | The exposures are deployment behaviour and move with implementations. The negotiation-failure claim rests on RFC 9846 and does not rot, and the gate keys the TTL to the OLDEST evidence anywhere under the axis, so a specification citation drives this clock too. A row whose only failure-mode evidence is a specification is carrying the wrong evidence for this TTL |

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

## Evidence provenance: what `independence` means, and what it deliberately does not

Added after review on [#46](https://github.com/OWASP/quantum-security-project/issues/46), where
@leprecha1 asked for reproducible criteria per value, an explicit way to say "not established", and
an assurance that mandatory classification does not become a substitute for verification. The first
two were simply missing. The third took two attempts to answer honestly, and both failures are
recorded below, because the second one is instructive.

**Independence is a property of the evidence-to-claim pair, not of the document.** The same RFC is
first-party evidence of its own publication and third-party evidence about a protocol it merely
references. That is why the field sits on each evidence object rather than on a registry of sources,
and why the same URL can legitimately carry different values on two different rows.

**One axis per field.** The first round shipped `first-party | third-party |
independently-reproducible | unknown`, which conflated two questions: three of those values describe
the relation between the evidence's author and the subject of the claim, while `independently-
reproducible` describes a property of method. A vendor's own pinned test harness is both, and there
was no precedence rule, so the same evidence had two defensible values. Reproducibility moved to its
own optional `reproduction` field and the enum is now a single axis.

| Value | The test | Typical case |
|---|---|---|
| `first-party` | The author and the subject of the claim share an interest | A project's own source tree or release notes, about that project's behaviour; a specification, about its own contents |
| `derivative` | The author is not the subject, but the content restates the subject's assertion rather than establishing it | Trade press repeating a vendor announcement; a CVE record authored by the vendor's own CNA |
| `third-party` | The author is not the subject and did not take the subject's word for it | An independent test report; a measurement of someone else's deployed code; telemetry collected by an unrelated operator |
| `unknown` | Authorship or affiliation cannot be established from the source | Affiliation not stated and not resolvable |

**Apply them in that order; the order is the precedence rule.** `derivative` exists because the axis
was not exhaustive without it: a blog restating a vendor's release notes is not the subject, so it is
not first-party, and it took the subject's word for it, so it is not third-party. Under the previous
enum it had no correct value, which is how a required field gets a wrong answer entered sincerely.
Note where this puts a CVE **record**, as distinct from a third-party analysis **of** one. The CVE
Program's own rules put the supplier first in line but hedge it: the CNA Operational Rules say the CNA
with the most appropriate scope is "often, but not always, the Supplier of the Product in question"
(s3.1). Measured across 10,000 CVE records published August and September 2026, 44.2% were assigned by
a named non-supplier CNA, so `third-party` is not wrong by default across the corpus. It IS wrong for
the population this matrix covers, where the supplier normally is the assigner: OpenSSL and the Go
project are both CNAs for their own products. The first round's table gave "a CVE analysis" as a
typical third-party case without that distinction, and that was an error.

**`independence_basis` is required on every value.** One sentence naming who authored the evidence and
how that relates to this claim. The first round required it only on `unknown` and
`independently-reproducible`, arguing the other two were cheap to check against the source URL. That
argument was wrong on this repository's own evidence: the exemplar labelled RFC 10024 `third-party`
evidence for the claim that RFC 10024 is published, and labelled RFC 8446 `third-party` for a property
RFC 8446 defines. A URL shows a host, not an authorship. Requiring the sentence is what surfaces the
mislabel, and both are corrected in this commit.

**Nothing in this schema grades evidence, and that is the answer to the third point.** Two versions of
a grading rule were written and both were removed, because each rewarded the lie it was meant to
expose:

1. The first warned when an axis rested only on weak evidence. Measured against commit 40f737f:
   the honest exemplar as shipped earned ONE warning, the same row with `third-party` typed over
   every block earned NONE, and typing the strongest value over every block also earned none. The
   honest row looked worse than either fabrication of it.
2. The second added a warning for a *uniform* provenance answer across all four axes, which fixed
   that case and immediately rewarded a fabricated **mix** instead.

The pattern is the finding. Offline, nothing here can tell a true `third-party` label from a false
one, so any rule keyed to which label an author chose grades their typing. So the gate stopped
grading. What it does instead is harder to game and is what actually found bugs:

- The label is **mandatory** and must carry a justifying sentence.
- It is **printed next to the status it supports**, on every row, pass or fail:
  `implem=default-on/first-party`. A reader cannot see a status without seeing whose word it rests on.
- Everything that still warns or fails is an **absence** rather than a grade: a missing basis, no
  cited document carrying a publication date, an exposure with no evidence, a source under a reserved
  name, a breached TTL. An author cannot relabel their way out of an absence.

`tests/test_gate.py` asserts this directly: relabelling every block on a row, to any of the four
values, must not change how many warnings the row earns.

**`reproduction`** is optional, and earns a row nothing. Nothing here re-runs anything, so it is an
instruction to a human reader and the gate reports it as a count. That is deliberate: in the first
round the strongest-sounding enum value was the better-rewarded lie.

**Three residuals, stated rather than implied.**

1. **A plausible host still defeats this.** A row with `third-party` on every block, a one-line basis,
   invented excerpts marked `verbatim: yes`, dated today, under a host nobody can check offline,
   passes. It is committed as a test case named `plausible-host-fabrication-still-passes` so this
   cannot quietly become a claim that it does not. What **is** now rejected is a source whose host
   cannot carry a real citation. Two families: the documentation and non-resolvable **names**, taken
   from the IANA Special-Use Domain Names registry (`.test`, `.example`, `.invalid`, `.localhost`,
   `.local`, `.onion`, `.alt`, `example.com/.net/.org`, `home.arpa`, `service.arpa`,
   `resolver.arpa`) plus `.internal`, which ICANN reserved by board resolution and which is in no
   IETF registry; and any **IP literal that is not globally reachable**, which covers the RFC 5737
   and RFC 3849 documentation ranges along with loopback, link-local and RFC 1918. The registry
   holds further entries this does not list, such as the `in-addr.arpa` reverse zones, so this is
   the documentation-and-non-resolvable subset of it and not the whole thing. The attribution matters and
   the first version of this check got it wrong by citing RFC 2606 alone: RFC 2606 s2 reserves only
   the four top-level names, its s3 reports that IANA "also currently has" the three second-level
   names reserved, its s4 records IANA agreeing to "the four top level domain name reservations
   specified in this document", and **RFC 6761 updates RFC 2606** and is what the registry cites for
   all seven. Citing 2606 bare is the outdated-citation pattern this repo complains about.
   This kills the specific fabricated row that motivated these changes, it needs no network, and it is
   the only part of gap 3 that can be a gate rather than a warning.
2. **`unknown` is not an exemption.** It describes the evidence, not a floor status, so it does not
   relax a TTL and does not excuse a status from needing evidence.
3. **Provenance is not validity.** This schema records where a claim came from, which is cheap, and
   cannot assess whether the claim is true, which is not. The step that would turn provenance into
   verification is fetching `source` and confirming `excerpt` appears there; that is gap 3 and it is
   not done.

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
- A `source` or document `url` whose host cannot carry a real citation is rejected. That means the
  documentation and non-resolvable names in the IANA Special-Use Domain Names registry, plus ICANN's
  `.internal`, plus any IP literal that is not globally reachable. The fabricated row that motivated
  the #46 changes cited `https://example.invalid/...` on every axis and validated with exit 0, and
  three later evasions of this check were each measured rather than imagined: userinfo
  (`https://ref@example.com/`), percent-encoding, and an IP literal in RFC 5737's documentation
  range. The attribution matters too, and the first version got it wrong by citing RFC 2606 alone:
  **RFC 6761 updates RFC 2606** and is what the registry cites. This needs no network, so link rot
  and rate limits cannot make it flaky, which is what lets it be
  a gate rather than a warning. The check lives in `validate.py` rather than in the schema because
  expressing it as a pattern needs a negative lookahead no reviewer can audit by eye; the cost is that
  a consumer validating against the schema alone does not get it.
- `independence` is **read**, which it previously was not. It was required on every evidence object
  and no rule consulted it, so flipping every block on a row left the verdict byte-identical: a
  required field that nothing checked. It is now mandatory **with a justifying sentence on every
  value**, and it is printed beside the status it supports on every row, pass or fail
  (`implem=default-on/first-party`). What the gate deliberately does **not** do is grade it. See
  "Evidence provenance" above for the two grading rules that were written, measured, and removed for
  rewarding the fabrication over the honest row.
- The provenance printed for an axis comes only from the evidence that **earns** its status: the pairs
  that interoperate, the implementations that are actually `default_enabled`. Counting every block
  under the axis let a disinterested report that a pair **failed** speak for a claim that the pair
  works, which is the multi-vendor vendor-count defect one rule over.
- An entry in `known_exposures` with no evidence is **reported**. Version 2 could not express one:
  the item schema set `additionalProperties: false` with no evidence property, so all five exposures
  on the exemplar were unevidenced by contract, in the axis the proposal calls most important. Two of
  the five still are, and the gate says so on every run rather than letting them pass as structure.
- Discovery is recursive and case-insensitive, and a stray non-JSON file under `protocols/` is a
  failure, because a renderer may still read it.
- The gate **fails closed** in both directions that matter. Without `jsonschema` it exits 2 rather than
  printing success, and a missing or empty `top10.json` is refused rather than treated as an empty
  allowlist, which previously let a row cite a non-existent entry and validate.

`tests/test_gate.py` covers 72 behaviours, most of which exist because an earlier version of this gate
accepted a row it should have rejected. `tests/test_gate.py --mutate` disables one layer of the gate at
a time in a throwaway copy and re-runs everything, so the suite's dependence on each layer is
measurable rather than asserted.

The report splits by what each case expects, because the aggregate was uninterpretable: a case
expecting **rejection** can die when the exit code is forced to success, and a case expecting
acceptance cannot, since the mutant agrees with it. Mixing the two made that mutant's number drift
upward every time an acceptance case was added, which read as the suite weakening when it was the
metric mixing populations. Measured 2026-10-31, against 59 rejection cases and 13 acceptance cases:

| Mutant | Rejection cases killed | Acceptance cases killed |
|---|---|---|
| semantic layer returns no findings | 34 of 59 | 2 of 13 |
| schema layer yields no errors | 14 of 59 | 0 of 13 |
| exit code always reports success | 57 of 59 | 0 of 13 |

The two rejection cases that survive the exit-code mutant are the two that exit **2** through the
gate's own `die()` path, so they do not depend on the mutated return at all. That is the correct
result rather than a hole.

## Known gaps, stated rather than discovered later

These are limits of what is here, not a to-do list for the project.

1. **No renderer, and this is the most important gap.** A directory of JSON files is unreadable to a
   defender, and at the six to eight rows this should start with it is already unreadable.
   Without a generator someone will hand-maintain a Markdown table and the staleness problem reappears
   downstream in an artifact nothing validates. It is a small generator over `protocols/*.json` and it
   is next, but it is not in this drop.
2. **Document currency is not checked, for drafts OR for RFCs.** The schema requires a revision suffix
   on an Internet-Draft id, which catches an unversioned reference and **does not** catch a renamed or
   replaced one. A row citing `draft-kwiatkowski-tls-ecdhe-mlkem-00` validates today, and that is the
   exact stale citation this design is reacting to.
   **An obsoleted RFC is the same gap and is worse, because it looks settled.** Measured on this
   repository's own row on 2026-10-31: it cited RFC 8446 as the constitutive TLS 1.3 specification, and
   RFC 9846 obsoleted RFC 8446 on 2026-07-11, moving the quoted text from Section 4.4.4 to Section
   4.5.3. The gate passed it, and passed it for a structural reason rather than by luck: a superseded
   RFC still carries a publication date, so the rule demanding one is satisfied, and nothing available
   offline knows the document was obsoleted.
   Closing both needs the same CI step: resolve every cited id against the IETF Datatracker or the RFC
   Editor index and assert that a draft's revision is current and its state is not `replaced`, and that
   an RFC's `obsoleted_by` is empty. A hand-maintained list of superseded documents is deliberately NOT
   the answer here, because that list rots exactly the way the citations do. The exemplar's citations
   were checked by hand on 2026-10-30 and that check missed this; doing it by hand is the gap.
3. **No link checking and no content verification.** `source` must be `https://` and must not sit
   under a reserved name, and that is the whole of what is checked. Nothing fetches it,
   snapshots it, or confirms that `excerpt` appears there, so `verbatim: yes` remains an author's
   assertion. Two distinct failures of that field have now been found in this repository's own single
   row: two excerpts truncated immediately before a clause that qualified the claim, and one that was
   **not a literal substring of the cited file at all**, because `NEWS.md` hard-wraps it and the bullet
   quoted did not name the mechanism the row is about. A different bullet did.
   `verbatim` is now **defined**, which it was not: `yes` means the excerpt is a quotation of the
   source with whitespace normalised, and not that it is a byte substring of the served bytes. That
   definition matters for whoever closes this gap, because a byte check is the wrong primitive. It
   fails true rows whose source is hard-wrapped, which is most RFC and Markdown text, and it fails
   every HTML source, where the sentence a human quotes is split across markup. Four of this row's
   seven excerpts are in that position. A whitespace-normalised check works on all of them, and the
   reason an excerpt check still cannot be a gate is network dependence rather than anything about the
   source format. The exemplar's implementation evidence cites raw source files at pinned tags, where
   the excerpt is literal as well as normalised; that was checked against the fetched bytes in the
   commit that introduced it, which is not the same as being checked on every run.
4. **The review burden is real.** One row per mechanism class means up to 60 rows for 30 protocols,
   600 or more evidence blocks, and with these TTLs roughly 540 axis re-verifications a year. That is
   not sustainable by one person. Six to eight rows is the sane starting point: TLS twice, SSH twice,
   IKEv2, DNSSEC.
5. **No way to contest a cell.** One maintainer, one evidence block per claim. There is no `disputed`
   flag, no second attestation, and no way for a claim to carry two independent sources, which is the
   property that matters most when a source is first-party. Narrower than it was, and not closed:
   every axis now prints whose word its status rests on, and an unevidenced exposure is reported, so
   the condition is **visible**. Visible is not contestable. A reader who disagrees with a cell still
   has nowhere in the data to say so, and on this design that is the gap that matters most after the
   renderer.
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
8. **Bus factor: one.** There is no `maintainer_backup` on the exemplar at all. The previous wording
   here, and in the 2026-10-30 comment on #46, said the field "is empty, and it exists so that
   emptiness is visible"; the field is absent from the row, so nothing was visible and the sentence
   described a mechanism that was not there. The implementation axis has a 90-day TTL and the exemplar's implementation
   evidence is dated 2026-10-31, so that row's gate starts failing on **2027-01-30** if nobody
   refreshes it. Verified by running the gate against the row aged 90 and 91 days rather than by
   arithmetic. That is the design working as intended, and it also means a required check depends on
   one person.
9. **Protocol names are free text.** Normalising to alphanumerics catches `TLS1.3` against `TLS 1.3`;
   it does not catch `TLSv1.3`, so two contradictory rows can still coexist under different spellings.
   The fix is a controlled vocabulary: an enum, or a committed protocol registry. Not here.
10. **The suite asserts rejection, not the reason.** Most of the 59 rejection cases check only that
    the gate exits non-zero, not which rule fired, so an over-broad rule could satisfy several of them
    for the wrong reason. The mutation report and the population split are partial answers; asserting
    an expected message per case is the real one. This gap previously said "32 cases" while two
    sections earlier the same file said 36, which is the defect this whole document is about, found in
    its own text.

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
