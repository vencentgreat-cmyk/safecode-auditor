# Release Checklist

This document describes the steps to publish a new SafeCode Auditor release.

## Before tagging

- [ ] All CI checks pass on `main` (tests, lint, smoke).
- [ ] `ruff check .` and `ruff format --check .` pass clean.
- [ ] `python -m pytest -q` passes all tests.
- [ ] README.md accurately reflects the current feature set.
- [ ] CHANGELOG.md is up to date with changes since the last release.
- [ ] `safecode_auditor/__version__` is set to the new version.
- [ ] `safecode --list-rules` lists all supported rule IDs.

## Build

```bash
python -m pip install build
python -m build
```

This produces `dist/safecode_auditor-VERSION.tar.gz` (sdist) and
`dist/safecode_auditor-VERSION-py3-none-any.whl` (wheel).

## Smoke test the wheel

```bash
python -m venv /tmp/smoke-test
/tmp/smoke-test/bin/pip install dist/safecode_auditor-*.whl
/tmp/smoke-test/bin/safecode --help
/tmp/smoke-test/bin/safecode --list-rules
/tmp/smoke-test/bin/safecode examples --format json
rm -rf /tmp/smoke-test
```

## Tag

```bash
git tag -a vVERSION -m "Release vVERSION"
git push origin vVERSION
```

The `v0` floating tag should be updated to the new release for GitHub
Action consumers:

```bash
git tag -f v0 vVERSION
git push -f origin v0
```

**Policy:** `v0` always points at the latest stable release.  Consumers
who need reproducible CI should pin to a specific tag (e.g. `@v0.3.0`).

## GitHub Release

Create a GitHub Release from the new tag.  Publish the sdist and wheel
as release assets.

## PyPI (when available)

```bash
python -m pip install twine
twine upload dist/*
```

Prefer GitHub trusted publishing (OIDC) over API tokens when configured.