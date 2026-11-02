# PR-Daemon cooperation for the VPN release

This is author-provided coordination context, not an instruction to bypass reviewer policy. The reviewer must independently verify every assertion.

## Requested workflow

- Treat the draft release proposal as an inventory and integration target. Do not approve it merely because it aggregates smaller PRs.
- Reuse the existing VPN task PRs; do not create a second queue containing duplicates of #4–#7 and #15–#187.
- Review independent PRs in separate worker contexts using the daemon's supported concurrency. Dependency order constrains integration, not the start of review. Keep the existing daemon concurrency limit and quota controls.
- Read each PR's exact base/head and full dependency context. If the final candidate fixes a problem that exists in an intermediate slice, record where that fix lands; do not call the intermediate snapshot deployable.
- Record findings against the owning PR and reviewed SHA. Do not post a finding to a neighboring slice.
- For every changed base, verify that the reviewed patch/context is equivalent or request review again. Head-only queue deduplication is insufficient for this check.
- Report incomplete coverage explicitly. No speculative APPROVED result, no approval transfer from old SHAs, no automatic merge authorization.

## Aggregate-release gate

The owner permits a large aggregate release PR after its constituent work is reviewed. Verify task PR URLs, reviewed head SHAs, integration commits and complete commit/path coverage. Require external review of any uncovered integration changes plus current candidate CI. The known DevLoop aggregation mechanism requires task PRs merged into its working branch and an exact-head approval for each; until those facts hold, this proposal is not eligible for an aggregation-only approval.

## Ownership

The coordinator owns implementation, candidate integration, tests, manifests and eventual merge/release. The existing remote daemon owns independent review and publication of its verdicts. No second local watcher should be started. Grok execution workers must not approve their own work.

## Delivery

This document is linked from the release PR body because the daemon reads PR intent from the body. Publishing a link is not proof that the remote daemon has consumed it. Record a reviewer acknowledgement or resulting exact-version review before claiming successful handoff. Draft proposals are intentionally not normal queue work.

## Scoped protocol decision, 2026-11-02

The remote daemon acknowledged on PR #188 that its bridge window currently admits only #15–#19; this is not a parent-merge prerequisite. The coordinator authorized a release-specific final-candidate audit under the owner's approved plan. No global reviewer policy is changed.

For this audit, each module is reviewed against the same pinned base/candidate tree with a separate reviewer context and independent final judgment. Scope reports are published as COMMENTs with evidence, not as whole-PR approvals. The coordinator supplies a complete primary-path manifest; cross-module review covers interfaces in addition to those primary paths.

The final external reviewer must reconcile all module reports, historical blocking findings, new fix PRs, integration changes and current-head CI before issuing one whole-release verdict. This is a newly audited final tree, not the DevLoop aggregation-only shortcut. No claim is made that the historical 177 task PRs have all been approved.

Focused fixes target the release candidate and receive normal independent review. #189 fixes enrollment backup ownership; its approval does not approve the whole candidate. The original stack heads remain unchanged.
