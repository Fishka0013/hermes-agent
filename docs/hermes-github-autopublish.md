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
