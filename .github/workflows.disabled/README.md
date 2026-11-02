# Workflows — DISABLED in mhrsdev/Vpn

All GitHub Actions workflows from the upstream project are disabled here by
renaming `workflows/` to `workflows.disabled/`. GitHub only runs workflows
that live directly under `.github/workflows/`, so nothing here can trigger —
no CI minutes, no scheduled crowd/fresh/harvest jobs, no tag-triggered
releases.

Why: this project builds and releases locally on the maintainer's own
machine (see `docs/` build notes). GitHub-hosted runners are intentionally
not used.

To re-enable (not recommended without review):
  git mv .github/workflows.disabled .github/workflows
and audit each file's triggers first — especially `fresh.yml`, `crowd.yml`,
`harvest.yml` (scheduled) and `release.yml` (fires on `v*` tags).
