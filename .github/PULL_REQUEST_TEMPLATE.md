<!--
Thanks for contributing to @hiprax/crypto. Please fill in the sections below
so reviewers can land your change quickly. Security-sensitive changes (key
derivation, wire format, IV/salt handling) get extra scrutiny — call them
out explicitly.
-->

## Summary

<!-- 1-3 sentences on what changed and why. Link the issue if there is one. -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (API removed/renamed, wire format changed, Node floor raised)
- [ ] Docs / dev-tooling only

## Security impact

- [ ] No security-sensitive code touched.
- [ ] Security-sensitive code touched — describe the threat model implication below.

<!-- If checked above: what guarantee changes? What invariant did you preserve? -->

## Checklist

- [ ] `npm run build` passes
- [ ] `npm run lint` passes
- [ ] `npm run type-check` passes
- [ ] `npm test` passes (including new/updated tests for the changed code)
- [ ] `CHANGELOG.md` updated with a dated entry under a new `## Unreleased` or version heading
- [ ] `README.md` updated if user-facing behaviour, public API, or architecture changed
- [ ] No new runtime dependencies added (or, if added, justified in the PR body)
