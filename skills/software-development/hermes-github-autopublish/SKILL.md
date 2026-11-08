---
name: hermes-github-autopublish
description: "Automatically deliver authorized Hermes code changes for Fishka0013/hermes-agent as an isolated worktree, tested commit, create-only task branch and GitHub Pull Request, without manual Git commands."
version: 1.0.0
platforms: [macos, linux]
metadata:
  hermes:
    tags: [github, autopublish, automatic-pr, git, worktree, tests]
    category: software-development
---

# Auto-deliver Hermes coding work

Use this skill when Owner asks to implement or fix code in the exact
Fishka0013/hermes-agent repository. Run the installed
~/.local/bin/hermes-gh-autopublish helper. Do NOT edit the active Gateway
release or the existing dirty ~/.hermes/hermes-agent checkout.

Before coding:
1. Choose a unique lowercase task slug, e.g. fix-metrics-20261108.
2. Run: hermes-gh-autopublish prepare --task SLUG
3. Edit only the printed task worktree and run relevant tests.

After coding:
1. Check the complete diff and ensure no secrets or irrelevant files.
2. Run: hermes-gh-autopublish publish --task SLUG --title "Summary" --test-command "python3 -m unittest ..."
3. Return PR URL, exact commit and verified test result. No manual Owner Git steps.

On timeout, ambiguous result, existing remote branch or unexpected error,
STOP; never retry push. Use hermes-gh-autopublish status --task SLUG and
perform independent read-only reconciliation.

Do not merge PRs, push to main, create tags/releases, deploy production, modify
GitHub settings, expose/change credentials or run paid services. A new approval
is required for work outside this low-risk PR-only boundary.
