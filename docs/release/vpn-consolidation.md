# VPN release consolidation

Owner authorization: 2026-11-02. Keep small changes independently reviewed; one aggregate release PR may exceed the normal size budget. The exception does not waive review coverage, other blocking rules, CI or integration validation.

## Frozen starting point

| Item | Revision |
| --- | --- |
| main | `fe13b0ef2fd0d009fae6d296a5c6a4cb89e66059` |
| candidate source, vpn/s/173 | `528e1990dace6815be4e7eef06283a2d084d3fe0` |
| candidate source tree | `e5e39fe50fed725619a8b85d49c18bf7b0b41de3` |

The source contains four original VPN PRs (#4–#7) followed by 173 slices (#15–#187). Original PRs #8–#13 were closed in favor of those slices. Their branches are historical evidence, not additional release inputs. Protocol PR #14 and documentation PR #2 are outside this VPN release.

At initialization, review coverage is incomplete and the source integration CI fails `TestR5OConfigOwner` with `config.json.bak: permission denied`. Old reports and approvals are not proof that the current candidate passes.

## Execution and ownership

1. Preserve source refs, PR inventory and recoverable history before cleanup.
2. Create an isolated candidate from the source above. Existing worker worktrees and historical PR heads stay untouched.
3. Run independent Grok execution tasks for the ownership regression, daemon capability verification and complete final-tree review coverage. The coordinator validates and integrates their results.
4. Publish a draft release proposal with a review manifest and explicit gaps. Draft means not ready for daemon approval or merge.
5. Reuse existing review evidence where its exact scope, head and base still apply. The remote daemon can review independent PRs concurrently in separate contexts; review does not require the predecessor to be merged first.
6. Submit new fixes as focused PRs. Do not reconstruct 173 duplicate PRs or rewrite the whole stack on each finding.
7. Integrate in dependency order with provenance checks. Review the integration delta and cross-module interactions, then run the full gate on the actual candidate combined with current main.
8. Merge/release only after all gates below pass. Close superseded PRs and remove unused branches only after accepted provenance preservation and active-owner checks.

## Review contract

See [PR-Daemon cooperation](pr-daemon-cooperation.md). The daemon remains an independent reviewer; Grok implementation reports are not daemon approvals. Its existing aggregate-release policy requires verified task PR approvals at their merged heads and no uncovered commits. A new release branch alone does not satisfy that policy.

Each coverage record includes base SHA, reviewed head SHA, path scope, external review URL/identity, verdict, integrated revision, and verification status. A base change requires an equivalence check or re-review, even if a head-only queue does not notice it. Changed code invalidates affected reviews; unchanged coverage can be reused only with recorded equivalence evidence.

## Acceptance gates

- Every changed path and every non-merge implementation commit is accounted for; old REQUEST_CHANGES findings have explicit dispositions.
- Independent external review covers the actual candidate, including interface behavior; no self-approval or transferred approval without proof.
- Current-head checks are green and the PR is mergeable. Missing/skipped evidence is not a pass.
- Unit/race, lint, licenses, builds, Docker integration and deployment/restore regression gates pass.
- Advertised platform installation, upgrade and rollback behavior has real-platform evidence, or the release scope explicitly excludes unverified support.
- Tag/release publication happens only after the accepted commit is fixed and artifacts/checksums are verified.

## Operating constraints

Use standard/default service only; Fast/priority forbidden. Preserve paused jobs and active worker ownership. Remote PR-Daemon is authoritative; do not start a local reviewer/watcher. Any newly configured status/CI/review poll uses 5 minutes. Unchanged polls do not rerun tests or spawn workers.

## Initial execution evidence

- Draft release proposal: [#188](https://github.com/iDoris-ai/iDoris-bridge/pull/188).
- Focused ownership regression fix: [#189](https://github.com/iDoris-ai/iDoris-bridge/pull/189).
- Baseline source passed go vet/race unit tests, lint (0 issues), license-notice checks for all six OS/architecture combinations, host/Linux builds, deployment Python tests (36) and deployment shellcheck.
- The focused fix passed independent coordinator enrollment race tests, Docker `TestR5OConfigOwner` and enrollment lint. Full integration and external approval remain pending.
- Three isolated Grok workers produced the repair, daemon capability analysis and final-tree coverage work. The coordinator separately checked the patch and tests.
- Existing remote daemon acknowledged the coordination request on #188. It confirmed that bridge's review window, rather than a main-only rule, is the queue bottleneck. The scoped final-tree audit protocol is recorded in the linked cooperation document and PR comments.

These are initialization results, not a release approval. Read current PR checks and exact-version external reports for subsequent status.
