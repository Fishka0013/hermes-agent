# Hermes GitHub autopublish v1 — automatic PR-only delivery

Exact repository: Fishka0013/hermes-agent; existing gh and Git credential
sessions are reused, never exported or reconfigured.

Workflow:
1. hermes-gh-autopublish prepare --task task-slug creates an isolated
   worktree from verified remote main.
2. Hermes changes files in that printed worktree and runs focused tests.
3. hermes-gh-autopublish publish --task task-slug --title "Summary"
   --test-command "python3 -m unittest ..." checks changed files, runs tests,
   commits, makes ONE create-only branch push and opens PR against main.
4. Hermes returns the PR URL and verified checks.

Limits: no direct main push, no force-push, no branch overwrite, no tags, no
auto-merge, no production deploy, no credential or security settings changes.
If a send result is ambiguous, the local exclusive intent blocks retry;
status --task task-slug performs read-only reconciliation.

This is a callable completion step for Hermes coding tasks, not a blind
scheduled upload of every local file. The scanner is defense-in-depth and
does not guarantee detection of every possible secret.

Revoke: stop using the skill and remove the user-level executable;
any open PR remains visible on GitHub. Deployment is separately authorized.


## Existing Owner Telegram milestones

The installed user-level wrapper enables the optional --notify-owner flag.
After successful prepare, it emits START; only after verified GitHub PR
creation does it emit DONE. An explicit STOP emits one PARTIAL. Events are
sent via the existing local ArchitectureRuntime owner_events.emit() and its
durable SQLite intent/attempt ledger; no bot, token or standalone daemon is
created. Direct publisher function tests do not send messages. If the
notification adapter is unavailable, the GitHub result remains truthful and
the CLI prints OWNER_NOTIFY=NOTIFIER_UNAVAILABLE or NOTIFY_ERROR.
Each task+phase has a stable OwnerEvent idempotency key. Ambiguous delivery
must not be blindly retried. This integration depends on the Mac's existing
ArchitectureRuntime; future VPS/remote execution needs an explicit provider
adapter and cannot silently assume that directory exists.
