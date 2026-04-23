# Contributing to AIAuth

Thank you for considering a contribution. AIAuth is operated by Finch Business
Services LLC as a small, focused security product. We welcome issues, PRs, and
RFC-style proposals — but we hold a high bar on simplicity and on the
zero-data-server guarantee.

## Before You Open a PR

- **Bug fixes and small improvements:** open a PR directly. Please describe
  the problem and the fix in the PR body, and link any related issue.
- **New features or changes to the receipt schema / API surface:** open an
  Issue first labeled `rfc` and describe the motivation, proposed design, and
  privacy implications. Schema changes are additive-only (see `CLAUDE.md` →
  "Schema Versioning Policy"). We'd rather discuss design before you invest
  implementation time.
- **Anything touching authentication, cryptography, or the anonymous
  registry:** please email security@aiauth.app before opening a public PR.

## Style and Testing

- Python: type hints on public functions; docstrings on new endpoints;
  parameterized SQL (no string interpolation).
- JavaScript (extension): no `eval`, no `new Function`, no remote scripts.
  The extension must pass Chrome Web Store review standards at all times.
- Run `python -c "import ast; ast.parse(open('server.py').read())"` before
  pushing server changes. Pytest suite lives in `tests/`.

## Licensing of Contributions

By opening a PR you agree that your contribution is licensed under the same
terms as the file you are modifying:

- Most of the repository is **Apache 2.0** (see `LICENSE`).
- Files under `self-hosted/` are **BUSL 1.1** (see `self-hosted/LICENSE.BUSL`).

## What We Won't Merge

- Code that phones home from the extension, agent, or self-hosted server.
- Features that require the public server to retain receipt content,
  behavioral metadata, or plaintext identifiers.
- Dependencies that ship pre-compiled native binaries without a verifiable
  build process.
- Feature flags that are on by default but undocumented.

## Code of Conduct

Be kind and be specific. Review comments address code, not authors. Assume
good faith; ask clarifying questions before escalating.

## Questions

`hello@aiauth.app` for anything not covered here.
