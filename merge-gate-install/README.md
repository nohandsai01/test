# Installation preparation

This directory contains a non-executable workflow template for the external-account Merge Gate acceptance.

It is intentionally not under `.github/workflows/` because activation currently lacks:

- owner-authorized GitHub App installation/repository selection;
- owner-authorized branch ruleset or protection changes;
- a trusted hosted check issuer and authoritative last-push source;
- closure of PR 281's current required-check failure and three unresolved review threads;
- independent exact-head QA and Security approval.

The candidate action reference is immutable, but it is not an approved hosted-runtime release. Do not activate the template or claim enforcement until all reserved gates are satisfied.
