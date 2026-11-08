# Hermes Owner platform: product contract and future deployment boundaries

Status: TARGET / implementation roadmap, **not** business CURRENT or a
deployment authorization. Owner makes final decisions.

## System responsibilities

- Mac + Hermes: development/control plane, model selection, code tasks,
  scheduling, observability. Mac sleep must not interrupt future VPS services.
- GitHub: versioned source, isolated branches, automatic pull requests,
  checks and explicit release/promotion policy. GitHub is **not** the runtime
  database or backup of customer information.
- Linux VPS (future): durable tasks, database, metrics, recovery, backup,
  container images and staged rollouts. VPS purchase and network setup
  belong to Server owner, not Hermes merely because Hermes can connect.
- Short-term-rental owner: pricing, business decisions, market source policy,
  calendar, reports and retained datasets. Hermes can analyze with consent
  but does not become owner of rental business truth.

## Existing Windows bot — preserve

The working Windows registration bot currently has one registration function.
Do not rewrite, relocate, refactor or switch it off during Hermes completion.
Treat its existing runtime as separate from rental market collection.

## Geographic collection

For Kufar, Owner expects that the source must be reached from Belarus. When
confirmed and permitted by the source, run the **collection worker** on a
Belarus network node and securely transfer structured results elsewhere.
Hermes, the main database and report engine need not be in Belarus. For Avito
and further sources, verify rules, network prerequisites and source-specific
permission separately; never assume one location is appropriate for all.
Avoid bypassing technical restrictions or platform terms.

## Gate A — GitHub code delivery

An authorized coding task is worked in an isolated task worktree; local tests
run; safe changes go to a unique create-only branch with one push and a PR.
Existing local work remains untouched. On ambiguous network response, stop,
preserve the intent and inspect remote state; never blindly retry a push.

A new standalone delivery CI tests both Python 3.11 and 3.14, including a
providerless local Git end-to-end flow. It checks patch hygiene, basic code
syntax, suspicious secrets and some path types. It **does not** constitute
full Hermes engine regression, runtime security certification or license
review. Critical core/auth/workflow changes require separate trusted review.

## Gate B — agent autonomy

Prove with a separately authorized provider/credential path that Hermes
independently selects the GitHub publishing skill after a small normal coding
request, without extra Owner prompts. Record provider model, usage,
test result, branch, commit, PR and any error. Never imply a configured
fallback model is usable without an authenticated successful test.
OAuth token refresh or credential modifications require their own approval.

## Gate C — runtime and server

Verify Gateway and CLI identities separately, cron delivery, model usage,
restart recovery, permissions A/B/C, logs and disaster-recovery procedure.
For a VPS, first measure CPU/RAM/storage/egress, then price and choose Linux
hosting. Deploy staging containers with health checks, backups and restore
tests; only then consider production cutover with explicit rollback receipts.

## Gate D — rental analytics

Use owner-current project materials and existing Kufar experiments rather
than recreating them. Store source, collection timestamp, normalization and
change history; deduplicate listings; validate freshness/quality; compute
market metrics deterministically; use Hermes for explainable summaries and
recommendations. Keep guests/private data and all credentials off public
GitHub. Start with one legal source and one daily report, then expand.

## Open blockers at authorship

- Existing upstream Blacksmith-targeted GitHub Actions remain queued on
  the fork. They are not an accepted full test gate.
- GitHub ruleset requires upstream context 'All required checks pass'.
  Do not change it to a lighter context without separately approved risk
  review and a demonstrated successful replacement lane.
- Native Hermes self-selection of the skill remains unproved: the configured
  free Nous Portal route failed for missing access token.
- Server size/cost, location and operator budget: UNKNOWN.
- No VPS purchase, Gateway promotion, OAuth refresh, Windows bot migration or
  business-current rewrite is implied by this document.
